import { openai } from '@ai-sdk/openai'
import { streamText } from 'ai'

export async function POST(req: Request) {
  const { messages } = await req.json()
  if (!process.env.OPENAI_API_KEY) return new Response('missing key', { status: 500 })
  const result = streamText({ model: openai('gpt-4o-mini'), messages })
  return result.toDataStreamResponse()
}
