// routes/instagram.js
const express = require("express");
const router = express.Router();

let cache = { data: null, time: 0 };

router.get("/posts", async (req, res) => {
  try {
    // 30 min cache, taaki API limit na lage
    if (cache.data && Date.now() - cache.time < 30 * 60 * 1000) {
      return res.json(cache.data);
    }

    const url =
      "https://graph.instagram.com/me/media" +
      "?fields=id,media_type,media_url,thumbnail_url,permalink" +
      "&limit=4&access_token=" + process.env.IG_TOKEN;

    const r = await fetch(url);
    const json = await r.json();
    if (json.error) throw new Error(json.error.message);

    const data = json.data.map((p) => ({
      id: p.id,
      image: p.media_type === "VIDEO" ? p.thumbnail_url : p.media_url,
      link: p.permalink,
    }));

    cache = { data, time: Date.now() };
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;