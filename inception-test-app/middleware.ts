import { clerkMiddleware, createRouteMatcher } from '@clerk/nextjs/server'

const isProtectedRoute = createRouteMatcher([
  '/dashboard(.*)',
  '/client(.*)',
  '/developer(.*)',
  '/engineering(.*)',
  '/delivery(.*)',
  '/tech-lead(.*)',
  '/qa(.*)',
  '/admin(.*)',
  '/projects(.*)',
])

export default clerkMiddleware(async (auth, req) => {
  if (isProtectedRoute(req)) {
    await auth.protect()
  }
})

export const config = {
  matcher: [
    '/((?!.*\\..*|_next).*)',
    '/',
    '/(api|trpc)(.*)',
  ],
}