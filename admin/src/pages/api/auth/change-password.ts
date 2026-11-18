/**
 * POST /api/auth/change-password
 * รับ { current_password, new_password } → ตรวจรหัสเดิม → บันทึกรหัสใหม่
 * แล้วออก JWT cookie ใหม่ (mustChangePassword = false)
 */
import type { APIRoute } from 'astro';
import bcrypt from 'bcryptjs';
import { getSession, signToken, makeLoginCookie } from '../../../lib/auth';
import { getAdminAuthById, setOwnPassword } from '../../../lib/db';

const DEFAULT_PASSWORD = '123456';
const MIN_LENGTH = 8;

function json(body: unknown, status = 200, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), {
    status, headers: { 'Content-Type': 'application/json', ...headers },
  });
}

export const POST: APIRoute = async ({ request }) => {
  const session = await getSession(request);
  if (!session) return json({ error: 'กรุณาเข้าสู่ระบบ' }, 401);

  let current = '', next = '';
  try {
    const body = await request.json();
    current = String(body.current_password ?? '');
    next    = String(body.new_password ?? '');
  } catch {
    return json({ error: 'Invalid request body' }, 400);
  }

  if (!current || !next) return json({ error: 'กรุณากรอกรหัสผ่านให้ครบ' }, 400);
  if (next.length < MIN_LENGTH) {
    return json({ error: `รหัสผ่านใหม่ต้องมีอย่างน้อย ${MIN_LENGTH} ตัวอักษร` }, 400);
  }
  if (next === DEFAULT_PASSWORD) return json({ error: 'ห้ามใช้รหัสผ่านเริ่มต้น 123456' }, 400);
  if (next === current) return json({ error: 'รหัสผ่านใหม่ต้องไม่ซ้ำกับรหัสผ่านเดิม' }, 400);

  const user = await getAdminAuthById(session.userId);
  if (!user) return json({ error: 'ไม่พบผู้ใช้งาน' }, 404);

  const match = await bcrypt.compare(current, user.password_hash);
  if (!match) return json({ error: 'รหัสผ่านปัจจุบันไม่ถูกต้อง' }, 400);

  await setOwnPassword(user.id, await bcrypt.hash(next, 10));

  const token = await signToken({
    userId: user.id, email: user.email, role: user.role ?? 'teacher', mustChangePassword: false,
  });
  return json({ ok: true }, 200, { 'Set-Cookie': makeLoginCookie(token) });
};
