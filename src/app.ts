import express from "express";
import cors from "cors";
import dotenv from "dotenv";

dotenv.config();


const app = express();

app.use(cors());
app.use(express.json());

const port = process.env.PORT || 3000;
app.get("/", (req, res) => {
  res.send(`running on port ${port || 3000}`);
});

export default app;


