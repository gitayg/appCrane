import { useEffect, useState } from 'react';
import { supabase } from './lib/supabase';
export default function App() {
  const [rows, setRows] = useState<any[]>([]);
  useEffect(() => { supabase.from('bookings').select('*').then(({ data }) => setRows(data ?? [])); }, []);
  return <div>{rows.length} bookings</div>;
}
