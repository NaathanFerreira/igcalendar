import { PrismaAdapter } from '@/lib/auth/prisma-adapter'
import { NextApiRequest, NextApiResponse, NextPageContext } from 'next'
import NextAuth, { NextAuthOptions } from 'next-auth'
import GoogleProvider, { GoogleProfile } from 'next-auth/providers/google'

export function buildNextAuthOptions(
  req: NextApiRequest | NextPageContext['req'],
  res: NextApiResponse | NextPageContext['res'],
): NextAuthOptions {
  return {
    // communication between next-auth and dabase, "transfer" information from user authenticated with google to database
    adapter: PrismaAdapter(req, res),
    // Configure one or more authentication providers
    providers: [
      GoogleProvider({
        clientId: process.env.GOOGLE_CLIENT_ID ?? '',
        clientSecret: process.env.GOOGLE_CLIENT_SECRET ?? '',
        authorization: {
          params: {
            // configuration to provide an refresh token
            prompt: 'consent',
            access_type: 'offline',
            response_type: 'code',
            // ask if user authorize to use following infos (email, profile and calendar)
            // scopes: https://developers.google.com/identity/protocols/oauth2/scopes?hl=pt-br
            scope:
              ' https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/calendar https://www.googleapis.com/auth/drive',
          },
        },
        // data that returns from the google user profile
        profile(profile: GoogleProfile) {
          return {
            id: profile.sub,
            name: profile.name,
            username: '',
            email: profile.email,
            avatar_url: profile.picture,
          }
        },
      }),
      // ...add more providers here
    ],
    // functions called in certain moments of the auth process
    callbacks: {
      // function called when user finish signIn
      async signIn({ account }) {
        // if user denied the calendar access authorization
        if (
          !account?.scope?.includes('https://www.googleapis.com/auth/calendar')
        ) {
          return '/register/connect-calendar/?error=permissions'
        }

        return true
      },
      // data that return form session = useSession()
      async session({ session, user }) {
        return {
          ...session,
          user,
        }
      },
    },
  }
}

// https://next-auth.js.org/configuration/initialization#advanced-initialization
export default async function auth(req: NextApiRequest, res: NextApiResponse) {
  return NextAuth(req, res, buildNextAuthOptions(req, res))
}
