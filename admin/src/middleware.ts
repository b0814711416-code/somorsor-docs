/**
 * middleware.ts — Astro Middleware
 * ทำงานก่อนทุก request: ตรวจสอบว่า login แล้วหรือยัง
 * ถ้ายังไม่ login และไม่ใช่หน้า /login หรือ /api/auth/* → redirect ไป /login
 * ถ้า login แล้วแต่ยังใช้รหัสเริ่มต้น (mustChangePassword) → บังคับไปหน้า /change-password
 */
import { defineMiddleware } from 'astro:middleware';
import { getSession } from './lib/auth';

// หน้า/route ที่ไม่ต้องการ auth
const PUBLIC_PATHS = ['/login', '/api/auth/login', '/api/debug', '/api/rebuild-status'];

// หน้า/route ที่ใช้ได้ระหว่างถูกบังคับเปลี่ยนรหัสผ่าน
const CHANGE_PASSWORD_PATHS = ['/change-password', '/api/auth/change-password', '/api/auth/logout'];

export const onRequest = defineMiddleware(async (context, next) => {
  const { pathname } = new URL(context.request.url);

  // อนุญาต public paths ผ่านได้เลย
  if (PUBLIC_PATHS.some(p => pathname.startsWith(p))) {
    return next();
  }

  // ตรวจ session จาก cookie
  const session = await getSession(context.request);

  if (!session) {
    // ยังไม่ login → redirect ไปหน้า login
    return context.redirect('/login');
  }

  // ยังไม่ได้เปลี่ยนรหัสผ่านเริ่มต้น → ใช้ได้เฉพาะหน้าเปลี่ยนรหัส/ออกจากระบบ
  if (session.mustChangePassword && !CHANGE_PASSWORD_PATHS.some(p => pathname.startsWith(p))) {
    if (pathname.startsWith('/api/')) {
      return new Response(JSON.stringify({ error: 'กรุณาเปลี่ยนรหัสผ่านก่อนใช้งาน' }), {
        status: 403, headers: { 'Content-Type': 'application/json' },
      });
    }
    return context.redirect('/change-password');
  }

  // ผ่าน! ส่ง session ไปให้ทุก page ใช้งานผ่าน locals
  context.locals.session = session;
  return next();
});
