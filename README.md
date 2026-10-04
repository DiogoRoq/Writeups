# Security Writeups

A Jekyll site (theme: [just-the-docs](https://github.com/just-the-docs/just-the-docs)) collecting HTB box writeups, CTF solves, and security research notes, hosted on GitHub Pages.

**Live site:** https://DiogoRoq.github.io/Writeups/

## Structure

```
htb/        HTB machine writeups (one .md per box)
ctf/        CTF challenge writeups
research/   Standalone technique/CVE research
tools/      Tool notes
index.md    Home page
```

Each category has an `index.md` landing page with `has_children: true`; every writeup under it sets `parent: <Category Title>` in its front matter, which is all `just-the-docs` needs to build the sidebar nav automatically.

## Adding a new writeup

1. Drop a new `.md` file in the right folder (e.g. `htb/forest.md`).
2. Add front matter at the top:

   ```yaml
   ---
   layout: default
   title: Forest
   parent: HTB Writeups
   nav_order: 2
   ---
   ```

   (`parent` must match the category's `title:` exactly — see `htb/index.md`, `ctf/index.md`, etc. Bump `nav_order` so it sorts where you want.)
3. Write the content below the front matter as normal Markdown.
4. Commit and push — GitHub Pages rebuilds automatically.

## Local preview

```bash
bundle install
bundle exec jekyll serve
```

Then open `http://localhost:4000`.

## Scope / disclaimer

All writeups document work against authorized targets only — retired HackTheBox machines, CTF competitions, or personal lab environments — for educational purposes.
