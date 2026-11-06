import express from 'express';
import pg from 'pg';
import crypto from 'node:crypto';

const { Pool } = pg;
const app = express();
app.use(express.text({ type: '*/*', limit: '2mb' }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('railway.internal') ? false : { rejectUnauthorized: false }
});

const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Cache-Control': 'no-store',
  'Content-Type': 'application/json; charset=utf-8'
};

function send(res, status, data, extra = {}) {
  Object.entries({ ...cors, ...extra }).forEach(([k,v]) => res.setHeader(k,v));
  return res.status(200).send(JSON.stringify({ status, data, headers: extra }));
}
function fail(res, status, error) { return send(res, status, { error }); }

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const digest = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${digest}`;
}
function verifyPassword(password, stored) {
  try {
    const [salt, digest] = String(stored || '').split(':');
    const actual = crypto.scryptSync(password, salt, 64);
    const expected = Buffer.from(digest, 'hex');
    return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
  } catch { return false; }
}
const isoDate = v => {
  if (!v) return '';
  if (typeof v === 'string' && /^\d{4}-\d{2}-\d{2}/.test(v)) return v.slice(0,10);
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? '' : d.toISOString().slice(0,10);
};

async function migrate() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'staff',
      active BOOLEAN NOT NULL DEFAULT TRUE,
      session_version INTEGER NOT NULL DEFAULT 1,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at TIMESTAMPTZ NOT NULL
    );
    CREATE TABLE IF NOT EXISTS records (
      id BIGSERIAL PRIMARY KEY,
      number TEXT UNIQUE,
      identity_no TEXT NOT NULL DEFAULT '',
      first_name TEXT NOT NULL DEFAULT '',
      last_name TEXT NOT NULL DEFAULT '',
      neighborhood TEXT NOT NULL DEFAULT '',
      application_date DATE NOT NULL DEFAULT CURRENT_DATE,
      status TEXT NOT NULL DEFAULT 'received',
      data JSONB NOT NULL DEFAULT '{}'::jsonb,
      version INTEGER NOT NULL DEFAULT 1,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      created_by BIGINT NOT NULL REFERENCES users(id),
      updated_by BIGINT NOT NULL REFERENCES users(id),
      entered_by BIGINT REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS events (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id),
      action TEXT NOT NULL,
      record_id BIGINT REFERENCES records(id) ON DELETE CASCADE,
      detail TEXT NOT NULL DEFAULT '',
      at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS reminders (
      id BIGSERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT NOT NULL DEFAULT '',
      repeat_type TEXT NOT NULL,
      due_date DATE,
      day_of_month INTEGER,
      warning_days INTEGER NOT NULL DEFAULT 3,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      assigned_user_id BIGINT REFERENCES users(id),
      last_completed_date DATE,
      last_completed_by BIGINT REFERENCES users(id),
      created_by BIGINT NOT NULL REFERENCES users(id),
      updated_by BIGINT NOT NULL REFERENCES users(id),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS records_identity_idx ON records(identity_no);
    CREATE INDEX IF NOT EXISTS reminders_assigned_idx ON reminders(assigned_user_id);
  `);
}

async function userName(id) {
  if (!id) return '';
  const { rows } = await pool.query('SELECT name FROM users WHERE id=$1',[id]);
  return rows[0]?.name || '';
}
function publicUser(u) {
  return { id:Number(u.id), username:u.username, name:u.name, role:u.role, active:u.active, csrf:'shared-cloud' };
}
async function auth(token) {
  if (!token) return null;
  const { rows } = await pool.query(`
    SELECT s.token,s.expires_at,u.*
    FROM sessions s JOIN users u ON u.id=s.user_id
    WHERE s.token=$1 LIMIT 1`,[token]);
  const r = rows[0];
  if (!r || !r.active || new Date(r.expires_at) <= new Date()) {
    if (r?.token) await pool.query('DELETE FROM sessions WHERE token=$1',[token]);
    return null;
  }
  return publicUser(r);
}
async function addEvent(userId, action, recordId=null, detail='') {
  await pool.query('INSERT INTO events(user_id,action,record_id,detail) VALUES($1,$2,$3,$4)',[userId,action,recordId,detail]);
}
async function decorateRecord(r) {
  const data = r.data || {};
  return {
    ...data,
    id:Number(r.id), number:r.number, identity_no:r.identity_no,
    first_name:r.first_name, last_name:r.last_name, neighborhood:r.neighborhood,
    application_date:isoDate(r.application_date), status:r.status, version:r.version,
    created_at:new Date(r.created_at).toISOString(), updated_at:new Date(r.updated_at).toISOString(),
    created_by:Number(r.created_by), updated_by:Number(r.updated_by),
    entered_by:r.entered_by ? Number(r.entered_by) : null,
    created_by_name:await userName(r.created_by),
    updated_by_name:await userName(r.updated_by),
    entered_by_name:await userName(r.entered_by)
  };
}

app.options('*', (req,res) => { Object.entries(cors).forEach(([k,v])=>res.setHeader(k,v)); res.status(204).end(); });
app.get('/health', async (req,res) => {
  try { await pool.query('SELECT 1'); res.json({ok:true}); }
  catch(e){ res.status(500).json({ok:false}); }
});

app.post('/api/gateway', async (req,res) => {
  let envelope;
  try { envelope = JSON.parse(typeof req.body === 'string' ? req.body : JSON.stringify(req.body || {})); }
  catch { return fail(res,400,'Geçersiz istek.'); }

  const path = String(envelope?.path || '');
  const method = String(envelope?.method || 'GET').toUpperCase();
  const body = envelope?.body && typeof envelope.body === 'object' ? envelope.body : {};
  const token = typeof envelope?.token === 'string' ? envelope.token : '';
  const serverTime = new Date().toISOString();

  if (path === '/api/session' && method === 'GET') {
    const c = await pool.query('SELECT count(*)::int AS count FROM users');
    if (c.rows[0].count === 0) return send(res,200,{setup:true,local:false,server_time:serverTime});
    const u = await auth(token);
    return u ? send(res,200,{user:u,server_time:serverTime}) : fail(res,401,'Oturum açmanız gerekiyor.');
  }
  if (path === '/api/setup' && method === 'POST') {
    const c = await pool.query('SELECT count(*)::int AS count FROM users');
    if (c.rows[0].count > 0) return fail(res,409,'Kurulum zaten tamamlandı.');
    const username=String(body.username||'').trim().toLowerCase();
    const name=String(body.name||'').trim();
    const password=String(body.password||'');
    if (!/^[a-z0-9._-]{3,50}$/.test(username) || !name || password.length<4) return fail(res,400,'Geçerli kullanıcı adı, ad soyad ve en az 4 karakterli parola girin.');
    await pool.query('INSERT INTO users(username,name,password_hash,role,active) VALUES($1,$2,$3,$4,true)',[username,name,hashPassword(password),'admin']);
    return send(res,201,{ok:true});
  }
  if (path === '/api/login' && method === 'POST') {
    const username=String(body.username||'').trim().toLowerCase();
    const password=String(body.password||'');
    const q=await pool.query('SELECT * FROM users WHERE username=$1 LIMIT 1',[username]);
    const u=q.rows[0];
    if (!u || !u.active || !verifyPassword(password,u.password_hash)) return fail(res,401,'Kullanıcı adı veya parola hatalı.');
    const newToken=crypto.randomBytes(32).toString('hex');
    await pool.query('DELETE FROM sessions WHERE user_id=$1',[u.id]);
    await pool.query('INSERT INTO sessions(token,user_id,expires_at) VALUES($1,$2,NOW()+INTERVAL \'12 hours\')',[newToken,u.id]);
    return send(res,200,{ok:true,token:newToken});
  }

  const user = await auth(token);
  if (!user) return fail(res,401,'Oturum açmanız gerekiyor.');

  if (path === '/api/logout' && method === 'POST') {
    await pool.query('DELETE FROM sessions WHERE token=$1',[token]); return send(res,200,{ok:true});
  }
  if (path === '/api/users' && method === 'GET') {
    const q=await pool.query('SELECT id,username,name,role,active FROM users ORDER BY name');
    return send(res,200,{users:q.rows.map(publicUser)});
  }
  if (path === '/api/users' && method === 'POST') {
    if (user.role !== 'admin') return fail(res,403,'Yönetici yetkisi gerekir.');
    const username=String(body.username||'').trim().toLowerCase(), name=String(body.name||'').trim(), password=String(body.password||'');
    if (!username || !name || password.length<4) return fail(res,400,'Eksik kullanıcı bilgisi.');
    try {
      await pool.query('INSERT INTO users(username,name,password_hash,role,active) VALUES($1,$2,$3,$4,true)',[username,name,hashPassword(password),body.role==='admin'?'admin':'staff']);
      await addEvent(user.id,'Personel hesabı açıldı',null,username);
      return send(res,201,{ok:true});
    } catch { return fail(res,409,'Bu kullanıcı adı zaten var.'); }
  }

  if (path === '/api/reminders' && method === 'GET') {
    const q = user.role==='admin'
      ? await pool.query('SELECT * FROM reminders ORDER BY active DESC,id DESC')
      : await pool.query('SELECT * FROM reminders WHERE assigned_user_id=$1 ORDER BY active DESC,id DESC',[user.id]);
    const reminders=[];
    for (const r of q.rows) reminders.push({
      id:Number(r.id), title:r.title, description:r.description||'', repeat_type:r.repeat_type,
      due_date:isoDate(r.due_date), day_of_month:r.day_of_month, warning_days:r.warning_days,
      active:r.active, assigned_user_id:r.assigned_user_id?Number(r.assigned_user_id):null,
      assigned_user_name:await userName(r.assigned_user_id),
      last_completed_date:isoDate(r.last_completed_date),
      last_completed_by:r.last_completed_by?Number(r.last_completed_by):null,
      last_completed_by_name:await userName(r.last_completed_by)
    });
    return send(res,200,{reminders,server_time:serverTime});
  }
  if (path === '/api/reminders' && method === 'POST') {
    if (user.role !== 'admin') return fail(res,403,'Hatırlatma eklemek için yönetici yetkisi gerekir.');
    const assigned=Number(body.assigned_user_id);
    const q=await pool.query(`INSERT INTO reminders(title,description,repeat_type,due_date,day_of_month,warning_days,active,assigned_user_id,created_by,updated_by)
      VALUES($1,$2,$3,$4,$5,$6,true,$7,$8,$8) RETURNING *`,[
      String(body.title||'').trim(),String(body.description||'').trim(),String(body.repeat_type||''),
      body.due_date||null,body.day_of_month||null,Number(body.warning_days??3),assigned,user.id
    ]);
    await addEvent(user.id,'Hatırlatma eklendi',null,String(body.title||''));
    return send(res,201,{reminder:q.rows[0]});
  }

  let m = path.match(/^\/api\/reminders\/(\d+)(?:\/(complete|delete))?$/);
  if (m) {
    const id=Number(m[1]), action=m[2]||'';
    const q=await pool.query('SELECT * FROM reminders WHERE id=$1',[id]), r=q.rows[0];
    if (!r) return fail(res,404,'Hatırlatma bulunamadı.');
    if (method==='POST' && action==='complete') {
      if (user.role!=='admin' && Number(r.assigned_user_id)!==Number(user.id)) return fail(res,403,'Yalnızca size atanmış görevi tamamlandı olarak işaretleyebilirsiniz.');
      const active=r.repeat_type==='once'?false:r.active;
      await pool.query('UPDATE reminders SET last_completed_date=CURRENT_DATE,last_completed_by=$1,active=$2,updated_by=$1,updated_at=NOW() WHERE id=$3',[user.id,active,id]);
      await addEvent(user.id,'Hatırlatma tamamlandı',null,r.title);
      return send(res,200,{ok:true,completed_date:isoDate(new Date()),completed_by:user.id,completed_by_name:user.name});
    }
    if (method==='POST' && action==='delete') {
      if (user.role!=='admin') return fail(res,403,'Yönetici yetkisi gerekir.');
      await pool.query('DELETE FROM reminders WHERE id=$1',[id]);
      return send(res,200,{ok:true});
    }
  }

  if (path === '/api/records' && method === 'GET') {
    const q=await pool.query('SELECT * FROM records ORDER BY id DESC');
    const records=[]; for (const r of q.rows) records.push(await decorateRecord(r));
    return send(res,200,{records,server_time:serverTime});
  }
  if (path === '/api/records' && method === 'POST') {
    const identity=String(body.identity_no||'');
    const dupe=await pool.query("SELECT number FROM records WHERE identity_no=$1 AND status IN ('received','missing') LIMIT 1",[identity]);
    if (dupe.rows[0] && body.allow_duplicate!==true) return fail(res,409,`Bu kişi için bekleyen başvuru var: ${dupe.rows[0].number}.`);
    const q=await pool.query(`INSERT INTO records(identity_no,first_name,last_name,neighborhood,application_date,status,data,created_by,updated_by,entered_by)
      VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$8,$9) RETURNING *`,[
      identity,String(body.first_name||''),String(body.last_name||''),String(body.neighborhood||''),
      isoDate(body.application_date)||isoDate(new Date()),['received','missing','entered','cancelled'].includes(body.status)?body.status:'received',
      JSON.stringify(body),user.id,body.status==='entered'?user.id:null
    ]);
    const r=q.rows[0], number=`AKS-${new Date().getFullYear()}-${String(r.id).padStart(6,'0')}`;
    await pool.query('UPDATE records SET number=$1 WHERE id=$2',[number,r.id]); r.number=number;
    await addEvent(user.id,'Başvuru alındı',r.id,String(body.status||''));
    return send(res,201,{record:await decorateRecord(r)});
  }

  m=path.match(/^\/api\/records\/(\d+)(\/events)?$/);
  if (m) {
    const id=Number(m[1]);
    if (method==='GET' && m[2]) {
      const q=await pool.query(`SELECT e.action,e.at,e.detail,u.name AS person FROM events e JOIN users u ON u.id=e.user_id WHERE e.record_id=$1 ORDER BY e.id DESC`,[id]);
      return send(res,200,{events:q.rows});
    }
    const q=await pool.query('SELECT * FROM records WHERE id=$1',[id]), r=q.rows[0];
    if (!r) return fail(res,404,'Başvuru bulunamadı.');
    if (method==='GET') return send(res,200,{record:await decorateRecord(r)});
    if (method==='PUT') {
      if (Number(body.version)!==Number(r.version)) return fail(res,409,'Bu başvuru başka bir ekranda değiştirildi. Listeyi yenileyin.');
      const merged={...(r.data||{}),...body};
      const nq=await pool.query(`UPDATE records SET identity_no=$1,first_name=$2,last_name=$3,neighborhood=$4,application_date=$5,status=$6,data=$7::jsonb,version=version+1,updated_at=NOW(),updated_by=$8,entered_by=$9 WHERE id=$10 RETURNING *`,[
        String(body.identity_no??r.identity_no),String(body.first_name??r.first_name),String(body.last_name??r.last_name),String(body.neighborhood??r.neighborhood),
        isoDate(body.application_date)||isoDate(r.application_date),['received','missing','entered','cancelled'].includes(body.status)?body.status:r.status,
        JSON.stringify(merged),user.id,body.status==='entered'?(r.entered_by||user.id):null,id
      ]);
      await addEvent(user.id,'Başvuru güncellendi',id,'');
      return send(res,200,{record:await decorateRecord(nq.rows[0])});
    }
  }

  if (path === '/api/records/delete-completed' && method === 'POST') {
    if (user.role!=='admin') return fail(res,403,'Yönetici yetkisi gerekir.');
    const ids=Array.isArray(body.ids)?body.ids.map(Number).filter(Number.isInteger):[];
    const all=body.all_records===true||body.all_completed===true;
    const q=all?await pool.query('SELECT id,number FROM records'):await pool.query('SELECT id,number FROM records WHERE id=ANY($1::bigint[])',[ids]);
    if (!q.rows.length) return fail(res,400,'Silinecek başvuru bulunamadı.');
    await pool.query('DELETE FROM records WHERE id=ANY($1::bigint[])',[q.rows.map(x=>x.id)]);
    await addEvent(user.id,'Başvurular silindi',null,q.rows.map(x=>x.number).join(', '));
    return send(res,200,{ok:true,deleted:q.rows.length,numbers:q.rows.map(x=>x.number)});
  }

  return fail(res,404,'İşlem bulunamadı.');
});

await migrate();
const port = Number(process.env.PORT || 3000);
app.listen(port, '0.0.0.0', () => console.log('Akseki SYDV API listening on', port));
