import NextAuth from "next-auth"
import GitHub from "next-auth/providers/github"
import Google from "next-auth/providers/google"
import { DrizzleAdapter } from "@auth/drizzle-adapter"
import { createDb, Db } from "./db"
import { accounts, users, roles, userRoles } from "./schema"
import { eq } from "drizzle-orm"
import { getRequestContext } from "@cloudflare/next-on-pages"
import { Permission, hasPermission, ROLES, Role } from "./permissions"
import CredentialsProvider from "next-auth/providers/credentials"
import { hashPassword, comparePassword } from "@/lib/utils"
import { authSchema, AuthSchema } from "@/lib/validation"
import { generateAvatarUrl } from "./avatar"
import { getUserId } from "./apiKey"
import { verifyTurnstileToken } from "./turnstile"

const ROLE_DESCRIPTIONS: Record<Role, string> = {
  [ROLES.EMPEROR]: "皇帝（网站所有者）",
  [ROLES.DUKE]: "公爵（超级用户）",
  [ROLES.KNIGHT]: "骑士（高级用户）",
  [ROLES.CIVILIAN]: "平民（普通用户）",
}

// Cloudflare Pages Edge 运行时只能通过 getRequestContext().env 拿到
// `wrangler pages secret bulk` 推送的运行时 secrets，process.env 拿不到。
// 本地 `next dev` 则走 process.env，这里做兼容 fallback。
const getAuthEnv = (key: string): string | undefined => {
  try {
    const env = getRequestContext().env as unknown as Record<string, unknown>
    const value = env?.[key]
    if (typeof value === "string" && value.length > 0) {
      return value
    }
  } catch {
    // 非 Cloudflare 运行时（如本地 next dev 未 setupDevPlatform）忽略，走 process.env
  }
  return process.env[key]
}

const getDefaultRole = async (): Promise<Role> => {
  const defaultRole = await getRequestContext().env.SITE_CONFIG.get("DEFAULT_ROLE")

  if (
    defaultRole === ROLES.DUKE ||
    defaultRole === ROLES.KNIGHT ||
    defaultRole === ROLES.CIVILIAN
  ) {
    return defaultRole as Role
  }

  return ROLES.CIVILIAN
}

async function findOrCreateRole(db: Db, roleName: Role) {
  let role = await db.query.roles.findFirst({
    where: eq(roles.name, roleName),
  })

  if (!role) {
    const [newRole] = await db.insert(roles)
      .values({
        name: roleName,
        description: ROLE_DESCRIPTIONS[roleName],
      })
      .returning()
    role = newRole
  }

  return role
}

export async function assignRoleToUser(db: Db, userId: string, roleId: string) {
  await db.delete(userRoles)
    .where(eq(userRoles.userId, userId))

  await db.insert(userRoles)
    .values({
      userId,
      roleId,
    })
}

export async function getUserRole(userId: string) {
  const db = createDb()
  const userRoleRecords = await db.query.userRoles.findMany({
    where: eq(userRoles.userId, userId),
    with: { role: true },
  })
  return userRoleRecords[0].role.name
}

export async function checkPermission(permission: Permission) {
  const userId = await getUserId()

  if (!userId) return false

  const db = createDb()
  const userRoleRecords = await db.query.userRoles.findMany({
    where: eq(userRoles.userId, userId),
    with: { role: true },
  })

  const userRoleNames = userRoleRecords.map(ur => ur.role.name)
  return hasPermission(userRoleNames as Role[], permission)
}

export const {
  handlers: { GET, POST },
  auth,
  signIn,
  signOut
} = NextAuth(() => {
  const googleId = getAuthEnv("AUTH_GOOGLE_ID")
  const googleSecret = getAuthEnv("AUTH_GOOGLE_SECRET")

  return {
  secret: getAuthEnv("AUTH_SECRET"),
  // Cloudflare Pages 自定义域（如 qqemail.eu.org）必需，否则报 UntrustedHost
  // 前端表现同样是 Server error / error=Configuration
  trustHost: true,
  adapter: DrizzleAdapter(createDb(), {
    usersTable: users,
    accountsTable: accounts,
  }),
  providers: [
    GitHub({
      clientId: getAuthEnv("AUTH_GITHUB_ID"),
      clientSecret: getAuthEnv("AUTH_GITHUB_SECRET"),
      allowDangerousEmailAccountLinking: true,
      issuer: "https://github.com/login/oauth",
    }),
    // Google 为可选：空值时不注册，避免污染整个 Auth 配置导致 GitHub 也 Configuration
    ...(googleId && googleSecret
      ? [
          Google({
            clientId: googleId,
            clientSecret: googleSecret,
            allowDangerousEmailAccountLinking: true,
          }),
        ]
      : []),
    CredentialsProvider({
      name: "Credentials",
      credentials: {
        username: { label: "用户名", type: "text", placeholder: "请输入用户名" },
        password: { label: "密码", type: "password", placeholder: "请输入密码" },
      },
      async authorize(credentials) {
        if (!credentials) {
          throw new Error("请输入用户名和密码")
        }

        const { username, password, turnstileToken } = credentials as Record<string, string | undefined>

        let parsedCredentials: AuthSchema
        try {
          parsedCredentials = authSchema.parse({ username, password, turnstileToken })
          // eslint-disable-next-line @typescript-eslint/no-unused-vars
        } catch (error) {
          throw new Error("输入格式不正确")
        }

        const verification = await verifyTurnstileToken(parsedCredentials.turnstileToken)
        if (!verification.success) {
          if (verification.reason === "missing-token") {
            throw new Error("请先完成安全验证")
          }
          throw new Error("安全验证未通过")
        }

        const db = createDb()

        const user = await db.query.users.findFirst({
          where: eq(users.username, parsedCredentials.username),
        })

        if (!user) {
          throw new Error("用户名或密码错误")
        }

        const isValid = await comparePassword(parsedCredentials.password, user.password as string, getAuthEnv("AUTH_SECRET") ?? "")
        if (!isValid) {
          throw new Error("用户名或密码错误")
        }

        return {
          ...user,
          password: undefined,
        }
      },
    }),
  ],
  events: {
    async signIn({ user }) {
      if (!user.id) return

      try {
        const db = createDb()
        const existingRole = await db.query.userRoles.findFirst({
          where: eq(userRoles.userId, user.id),
        })

        if (existingRole) return

        const defaultRole = await getDefaultRole()
        const role = await findOrCreateRole(db, defaultRole)
        await assignRoleToUser(db, user.id, role.id)
      } catch (error) {
        console.error('Error assigning role:', error)
      }
    },
  },
  callbacks: {
    async jwt({ token, user }) {
      if (user) {
        token.id = user.id
        token.name = user.name || user.username
        token.username = user.username
        token.image = user.image || generateAvatarUrl(token.name as string)
      }
      return token
    },
    async session({ session, token }) {
      if (token && session.user) {
        session.user.id = token.id as string
        session.user.name = token.name as string
        session.user.username = token.username as string
        session.user.image = token.image as string

        const db = createDb()
        let userRoleRecords = await db.query.userRoles.findMany({
          where: eq(userRoles.userId, session.user.id),
          with: { role: true },
        })

        if (!userRoleRecords.length) {
          const defaultRole = await getDefaultRole()
          const role = await findOrCreateRole(db, defaultRole)
          await assignRoleToUser(db, session.user.id, role.id)
          userRoleRecords = [{
            userId: session.user.id,
            roleId: role.id,
            createdAt: new Date(),
            role: role
          }]
        }

        session.user.roles = userRoleRecords.map(ur => ({
          name: ur.role.name,
        }))

        const userAccounts = await db.query.accounts.findMany({
          where: eq(accounts.userId, session.user.id),
        })

        session.user.providers = userAccounts.map(account => account.provider)
      }

      return session
    },
  },
  session: {
    strategy: "jwt",
  },
  }
})

export async function register(username: string, password: string) {
  const db = createDb()

  const existing = await db.query.users.findFirst({
    where: eq(users.username, username)
  })

  if (existing) {
    throw new Error("用户名已存在")
  }

  const hashedPassword = await hashPassword(password, getAuthEnv("AUTH_SECRET") ?? "")

  const [user] = await db.insert(users)
    .values({
      username,
      password: hashedPassword,
    })
    .returning()

  return user
}
