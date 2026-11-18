/**
 * POST /api/auth/login
 * รับ { email, password } — email คือชื่อผู้ใช้ (เช่น chaiso01) หรืออีเมล → ตรวจสอบกับฐานข้อมูล → ออก JWT cookie
 */
import type { APIRoute } from 'astro';
import bcrypt from 'bcryptjs';
import { getAdminByEmail, updateLastLogin } from '../../../lib/db';
import { signToken, makeLoginCookie } from '../../../lib/auth';

export const POST: APIRoute = async ({ request }) => {
  // รับ JSON body
  let email: string, password: string;
  try {
    const body = await request.json();
    email    = (body.email    ?? '').trim().toLowerCase();
    // พิมพ์แบบเดิม chaiso01@school.ac.th → ตัดเหลือ chaiso01 อัตโนมัติ
    email    = email.replace(/@school\.ac\.th$/, '');
    password = (body.password ?? '');
  } catch {
    return new Response(JSON.stringify({ error: 'Invalid request body' }), {
      status: 400, headers: { 'Content-Type': 'application/json' },
    });
  }

  if (!email || !password) {
    return new Response(JSON.stringify({ error: 'กรุณากรอกชื่อผู้ใช้และรหัสผ่าน' }), {
      status: 400, headers: { 'Content-Type': 'application/json' },
    });
  }

  // ค้นหา admin user
  const user = await getAdminByEmail(email);
  if (!user) {
    // ป้องกัน timing attack — compare กับ hash ตัวอย่างก่อนตอบ
    await bcrypt.compare(password, '$2b$10$invalidhashxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx');
    return new Response(JSON.stringify({ error: 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง' }), {
      status: 401, headers: { 'Content-Type': 'application/json' },
    });
  }

  // ตรวจสอบรหัสผ่าน
  const match = await bcrypt.compare(password, user.password_hash);
  if (!match) {
    return new Response(JSON.stringify({ error: 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง' }), {
      status: 401, headers: { 'Content-Type': 'application/json' },
    });
  }

  // ออก JWT token
  const mustChangePassword = Boolean(user.must_change_password);
  const token = await signToken({
    userId: user.id, email: user.email, role: user.role ?? 'teacher', mustChangePassword,
  });
  await updateLastLogin(user.id);

  return new Response(JSON.stringify({ ok: true, displayName: user.display_name, mustChangePassword }), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Set-Cookie': makeLoginCookie(token),
    },
  });
};
