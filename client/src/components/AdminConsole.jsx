import { useEffect, useState } from "react";

const apiUrl = import.meta.env.VITE_API_URL || "";
const pageSize = 25;

function displayValue(value) {
  if (value === null || value === undefined) return "NULL";
  return typeof value === "object" ? JSON.stringify(value) : String(value);
}

function initialValue(value, type) {
  if (type === "json") return JSON.stringify(value ?? null, null, 2);
  return value ?? "";
}

export default function AdminConsole({ account, onBack, onSignOut }) {
  const [tables, setTables] = useState([]);
  const [tableName, setTableName] = useState("");
  const [tableData, setTableData] = useState(null);
  const [offset, setOffset] = useState(0);
  const [selectedRow, setSelectedRow] = useState(null);
  const [resetTarget, setResetTarget] = useState(null);
  const [resetPassword, setResetPassword] = useState("");
  const [formValues, setFormValues] = useState({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  async function request(url, options = {}) {
    const response = await fetch(url, options);
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Database admin request failed.");
    return data;
  }

  async function loadTables() {
    try {
      const data = await request(`${apiUrl}/api/admin/tables`);
      setTables(data.tables);
      if (!tableName && data.tables.length) setTableName(data.tables[0].name);
    } catch (requestError) {
      setError(requestError.message);
    }
  }

  async function loadRows(name = tableName, currentOffset = offset) {
    if (!name) return;
    setBusy(true);
    setError("");
    try {
      setTableData(await request(`${apiUrl}/api/admin/tables/${encodeURIComponent(name)}?limit=${pageSize}&offset=${currentOffset}`));
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    loadTables();
  }, []);

  useEffect(() => {
    if (tableName) loadRows(tableName, offset);
  }, [tableName, offset]);

  function beginEdit(row) {
    setSelectedRow(row);
    setFormValues(Object.fromEntries(tableData.table.editable.map((column) =>
      [column, initialValue(row[column], tableData.table.types[column])]
    )));
    setError("");
    setNotice("");
  }

  async function saveRow(event) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const values = {};
      for (const [column, value] of Object.entries(formValues)) {
        const type = tableData.table.types[column];
        values[column] = type === "json" ? value : type === "integer" ? value === "" ? null : Number(value) : type === "boolean" ? value === "true" : value;
      }
      await request(`${apiUrl}/api/admin/tables/${encodeURIComponent(tableName)}/${encodeURIComponent(selectedRow[tableData.table.primaryKey])}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ values })
      });
      setSelectedRow(null);
      setNotice("Row updated.");
      await loadRows();
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBusy(false);
    }
  }

  async function deleteRow(row) {
    const key = row[tableData.table.primaryKey];
    if (!window.confirm(`Delete this row from ${tableName}? Related rows may also be removed.`)) return;
    setBusy(true);
    setError("");
    try {
      await request(`${apiUrl}/api/admin/tables/${encodeURIComponent(tableName)}/${encodeURIComponent(key)}`, { method: "DELETE" });
      setNotice("Row deleted. Related data follows database cascade rules.");
      await loadRows();
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBusy(false);
    }
  }

  async function resetAccountPassword(event) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await request(`${apiUrl}/api/admin/accounts/${encodeURIComponent(resetTarget.id)}/reset-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: resetPassword })
      });
      setResetTarget(null);
      setResetPassword("");
      setNotice(`Password reset for @${resetTarget.username}; existing sessions were revoked.`);
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBusy(false);
    }
  }

  const page = Math.floor(offset / pageSize) + 1;
  const pages = Math.max(1, Math.ceil((tableData?.total ?? 0) / pageSize));

  return <main className="shell admin-shell">
    <header className="topbar">
      <a className="brand" href="#" onClick={onBack}><span className="brand-mark">D</span><span>depguard<span className="brand-dot">.</span></span></a>
      <div className="account-menu"><span className="account-label">@{account.username} · ADMIN</span><button className="nav-action" onClick={onBack}>Scanner</button><button className="nav-action" onClick={onSignOut}>Sign out</button></div>
    </header>
    <section className="admin-content">
      <div className="admin-heading"><div><p className="admin-kicker">DATABASE CONTROL</p><h1>Stored records</h1><p>Review and edit saved accounts, scans, dependencies, and advisory evidence.</p></div><span className="admin-lock">ADMIN ACCESS</span></div>
      <div className="schema-notice">Column definitions and database schema are managed through reviewed SQL migrations. This console edits and deletes table rows and their values, not schema.</div>
      <div className="admin-toolbar">
        <label>Table
          <select aria-label="Select database table" value={tableName} onChange={(event) => { setOffset(0); setNotice(""); setTableName(event.target.value); }}>
            {tables.map((table) => <option value={table.name} key={table.name}>{table.name}</option>)}
          </select>
        </label>
        <span>{tableData ? `${tableData.total.toLocaleString()} rows` : "Loading tables…"}</span>
      </div>
      {error && <div className="error-banner" role="alert">{error}</div>}
      {notice && <div className="admin-notice" role="status">{notice}</div>}
      <div className="admin-table-wrap">
        <table className="admin-table"><thead><tr>{tableData?.table.columns.map((column) => <th key={column}>{column}</th>)}<th>Actions</th></tr></thead>
          <tbody>{tableData?.rows.map((row) => <tr key={String(row[tableData.table.primaryKey])}>
            {tableData.table.columns.map((column) => <td key={column} title={displayValue(row[column])}><span className="admin-cell">{displayValue(row[column])}</span></td>)}
            <td><div className="admin-row-actions"><button onClick={() => beginEdit(row)}>Edit row</button>{tableName === "accounts" && row.id !== account.id && <button onClick={() => { setResetTarget(row); setResetPassword(""); setError(""); }}>Reset password</button>}<button className="danger-action" onClick={() => deleteRow(row)}>Delete</button></div></td>
          </tr>)}</tbody>
        </table>
        {!busy && tableData?.rows.length === 0 && <div className="empty">This table has no records.</div>}
        {busy && <div className="empty">Loading database records…</div>}
      </div>
      <div className="admin-pagination"><span>Page {page} of {pages}</span><div><button disabled={offset === 0 || busy} onClick={() => setOffset(Math.max(offset - pageSize, 0))}>Previous</button><button disabled={!tableData || offset + pageSize >= tableData.total || busy} onClick={() => setOffset(offset + pageSize)}>Next</button></div></div>
      <p className="admin-footnote">Passwords and raw session tokens are never exposed. Deleting a parent record can cascade to its dependent rows.</p>
    </section>
    {selectedRow && <div className="admin-modal-backdrop" role="presentation">
      <section className="admin-modal" role="dialog" aria-modal="true" aria-labelledby="edit-row-title">
        <div className="admin-modal-head"><div><p className="admin-kicker">EDIT {tableName}</p><h2 id="edit-row-title">Update row values</h2></div><button className="nav-action" onClick={() => setSelectedRow(null)}>Close</button></div>
        <form onSubmit={saveRow}>
          <div className="admin-fields">{tableData.table.editable.map((column) => <label key={column}>{column}
            {column === "role" ? <select value={formValues[column]} onChange={(event) => setFormValues({ ...formValues, [column]: event.target.value })}><option value="user">user</option><option value="admin">admin</option></select>
              : column === "archived" ? <select value={String(formValues[column])} onChange={(event) => setFormValues({ ...formValues, [column]: event.target.value })}><option value="true">true</option><option value="false">false</option></select>
                : tableData.table.types[column] === "json" ? <textarea rows={7} spellCheck="false" value={formValues[column]} onChange={(event) => setFormValues({ ...formValues, [column]: event.target.value })} />
                  : <input type={tableData.table.types[column] === "integer" ? "number" : "text"} value={formValues[column]} onChange={(event) => setFormValues({ ...formValues, [column]: event.target.value })} />}
          </label>)}</div>
          <div className="admin-modal-actions"><button type="button" className="nav-action" onClick={() => setSelectedRow(null)}>Cancel</button><button className="primary-action" type="submit" disabled={busy}>{busy ? "Saving…" : "Save row"}</button></div>
        </form>
      </section>
    </div>}
    {resetTarget && <div className="admin-modal-backdrop" role="presentation">
      <section className="admin-modal" role="dialog" aria-modal="true" aria-labelledby="reset-password-title">
        <div className="admin-modal-head"><div><p className="admin-kicker">ACCOUNT ACCESS</p><h2 id="reset-password-title">Reset @{resetTarget.username}</h2></div><button className="nav-action" onClick={() => setResetTarget(null)}>Close</button></div>
        <form onSubmit={resetAccountPassword}>
          <label className="reset-password-field">New password<input type="password" autoComplete="new-password" minLength={12} maxLength={128} required value={resetPassword} onChange={(event) => setResetPassword(event.target.value)} /></label>
          <p className="admin-footnote">The new password is stored as a scrypt hash. Existing sessions for this account will be revoked.</p>
          <div className="admin-modal-actions"><button type="button" className="nav-action" onClick={() => setResetTarget(null)}>Cancel</button><button className="primary-action" type="submit" disabled={busy || resetPassword.length < 12}>{busy ? "Resetting…" : "Reset password"}</button></div>
        </form>
      </section>
    </div>}
  </main>;
}
