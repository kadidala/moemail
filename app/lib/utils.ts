import { type ClassValue, clsx } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export async function hashPassword(password: string, salt: string = process.env.AUTH_SECRET || ""): Promise<string> {
  const encoder = new TextEncoder()
  const data = encoder.encode(password + salt)
  const hash = await crypto.subtle.digest('SHA-256', data)
  return btoa(String.fromCharCode(...new Uint8Array(hash)))
}

export async function comparePassword(password: string, hashedPassword: string, salt: string = process.env.AUTH_SECRET || ""): Promise<boolean> {
  const hash = await hashPassword(password, salt)
  return hash === hashedPassword
}
