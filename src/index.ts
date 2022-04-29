import express from "express"
import routes from "./routes/index.js"

const app = express();
app.use(express.json());
app.disable("X-Powered-By");

app.use(routes())

app.listen(8080);