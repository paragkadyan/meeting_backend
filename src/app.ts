import express from "express";
import cors from "cors";

const app = express();

app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
  res.send(`running on port ${process.env.PORT || 3000}`);
});

export default app;


