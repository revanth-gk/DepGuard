import app from "./app.js";
import { initializeDatabase } from "./database.js";

const port = Number(process.env.PORT) || 4000;
await initializeDatabase();
app.listen(port, "0.0.0.0", () => console.log(`DepGuard API listening on ${port}`));
