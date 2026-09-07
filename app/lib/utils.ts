import { type ClassValue, clsx } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export async function hashPassword(password: string): Promise<string> {
  const encoder = new TextEncoder()
  let salt = ""
  try {
    const { getRequestContext } = await import("@cloudflare/next-on-pages")
    const env = getRequestContext().env as unknown as Record<string, unknown>
    if (typeof env?.AUTH_SECRET === "string") {
      salt = env.AUTH_SECRET
    } else {
      salt = process.env.AUTH_SECRET || ""
    }
  } catch {
    salt = process.env.AUTH_SECRET || ''
  }
  const data = encoder.encode(password + salt)
  const hash = await crypto.subtle.digest('SHA-256', data)
  return btoa(String.fromCharCode(...new Uint8Array(hash)))
}

export async function comparePassword(password: string, hashedPassword: string): Promise<boolean> {
  const hash = await hashPassword(password)
  return hash === hashedPassword
}
