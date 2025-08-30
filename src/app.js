import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";

const app = express();

// cross origin resource sharing 
app.use(cors({
    origin: process.env.CORS_ORIGIN,
    credentials: true
}))

// for handling json and API's
app.use(express.json({
    limit: "16kb" // max data size
}));

// handlind url data which is in encoded  as space is changed to %20
app.use(express.urlencoded({
    limit: "16kb", // max data size
    extended: true // for nested data
}));

app.use(express.static("public")); // for handling data stored locally like images , favicon , icons to easily access => a public folder is already initiated

app.use(cookieParser());


export { app };
