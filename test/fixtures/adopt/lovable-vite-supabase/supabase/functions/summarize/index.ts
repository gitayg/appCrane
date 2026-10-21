Deno.serve(async (req) => {
  const key = Deno.env.get('OPENAI_API_KEY');
  return new Response(JSON.stringify({ ok: !!key }), { headers: { 'Content-Type': 'application/json' } });
});
