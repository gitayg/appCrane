import { useEffect, useState } from "react";
import { supabase } from "@/integrations/supabase/client";

export default function Index() {
  const [todos, setTodos] = useState<any[]>([]);
  useEffect(() => {
    supabase.from('todos').select('*').then(({ data }) => setTodos(data || []));
    supabase.auth.getSession();
  }, []);
  return <ul>{todos.map((t) => <li key={t.id}>{t.title}</li>)}</ul>;
}
