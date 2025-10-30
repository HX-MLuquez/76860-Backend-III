const express = require("express");
const app = express();
const port = 3101;

app.get("/", (req, res) => {
  res.send("Hello World!www");
});

app.listen(port, () => {
  console.log(`Example app listening on port ---> http://localhost:${port}`);
});
