# Why

- https://x.com/janwilmake/status/1926690572099600500
- https://x.com/dread_numen/status/1930380519239496122
- https://x.com/EastlondonDev/status/1930379050997923846

# How

- Login with X (or my own oauth provider)
- `EditDurableObject`: ensures realtime sending and receiving of changes to markdown
- `ContextDO`: contains SQLite with all documents and all contexts of all users, augmented with metadata. Can be DORM to also have one per user/group/organisation but idk yet what makes most sense to shard on.
- sidebar: explorer with files/folders
- left: raw markdown (monaco or other lightweight js solution)
- right: pretty markdown with rich context-og-deluxe-embeds

# Try

https://lmpify.com/i-want-to-make-a-new-62v5nk0

doenst work yet. get example, make it work.

this one? https://github.com/carolkindell/multiple-rooms/blob/main/multiple-rooms/worker.js

this is a live file editor with unlimited subscribers.

usecase isn't just context; can also use monaco as an editor, making it much more than this.

but yeah, the starting point is a simple way for anyone using lmpify to keep their contexts somewhere. this state can only be managed by authenticated people but can be read (live) by anyone.

## Bookmarking context

❗️❗️❗️❗️❗️❗️❗️ Bookmark contexts: separate interface that I can just embed as js that allows adding contexts that I bookmark.

- Adds button 🔖 to topleft which opens/closes bookmarks sidepanel
- loads in all bookmarks through context.contextarea.com and renders in nice way showing url, title, tokens, og, may be a bit bigger
- button on every bookmark to remove bookmark or use
- also shows current textarea value ones on top with ability to bookmark
- search on top that searches over titles and urls

The state of bookmark contexts is just a flat list of urls and we can use localStorage to store that as `string[]`. Great thing about it is that we use the already authenticated api of context to expand it into something useful. The UI could just make it possible to send this `string[]` over to a predictable URL that is github-authorized, e.g. https://bookmarks.contextarea.com/janwilmake. This can be done by just using pastebin, then using https://bookmarks.contextarea.com/publish?url={url}. This would authenticate, then set the value, making it shareable everybody.

The 'personal context base' should be available publicly as well! this in turn allows turning this into a simple fetch mcp to gather a context prompt!
