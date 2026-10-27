import { useCallback, useEffect, useState } from "react";

export function useApi(fn) {
  const [state, setState] = useState({ data: null, error: null, loading: true });
  const load = useCallback(() => {
    setState((s) => ({ ...s, loading: true, error: null }));
    fn()
      .then((data) => setState({ data, error: null, loading: false }))
      .catch((e) => setState({ data: null, error: e.message, loading: false }));
  }, [fn]);
  useEffect(load, [load]);
  return { ...state, retry: load };
}
