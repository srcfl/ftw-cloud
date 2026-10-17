package oauth

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"rsc.io/qr"
)

// The authorize page. It is the one page FTW Cloud shows a person: who is
// asking, where they go back to, what they may do, and how to say yes. It
// waits on a server-sent event and never polls.

type pageData struct {
	Nonce        string
	RID          string
	Name         string
	Host         string
	Verified     bool
	FromDocument bool
	RedirectHost string
	Local        bool
	Scopes       []string
	Control      bool
	Code         string
	Link         string
	QR           template.HTML
}

type pageError struct {
	Nonce string
	Title string
	Text  string
	// Back is the client's error response, as a link the person may follow
	// to BackHost.
	Back     string
	BackHost string
}

func (s *Server) consentPage(w http.ResponseWriter, rid string, c consent) {
	u, _ := url.Parse(c.RedirectURI)
	d := pageData{Nonce: randomToken(16), RID: rid, Name: c.ClientName, Host: c.ClientHost, Verified: c.Verified, FromDocument: isCIMD(c.ClientID),
		RedirectHost: asciiHostPort(u), Local: u.Scheme == "http" && isLoopback(u.Hostname()),
		Code: showCode(c.Code), Link: appLink(rid, c.Offer)}
	for _, sc := range splitScope(c.Scope) {
		d.Scopes = append(d.Scopes, scopeWords[sc])
		if !slices.Contains(ReadScopes, sc) {
			d.Control = true
		}
	}
	d.QR = qrSVG(d.Link)
	pageHeaders(w, d.Nonce)
	w.WriteHeader(http.StatusOK)
	_ = consentTmpl.Execute(w, d)
}

func (s *Server) authorizePage(w http.ResponseWriter, status int, e pageError) {
	e.Nonce = randomToken(16)
	pageHeaders(w, e.Nonce)
	w.WriteHeader(status)
	_ = errorTmpl.Execute(w, e)
}

func pageHeaders(w http.ResponseWriter, nonce string) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", fmt.Sprintf("default-src 'none'; script-src 'nonce-%[1]s'; style-src 'nonce-%[1]s'; "+
		"img-src data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'", nonce))
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Strict-Transport-Security", "max-age=31536000")
}

// qrSVG draws text as a QR code, dark on light whatever the page's theme,
// with the quiet zone the standard asks for.
func qrSVG(text string) template.HTML {
	// Level L: the link carries the signed offer, and a screen is clean.
	code, err := qr.Encode(text, qr.L)
	if err != nil {
		return ""
	}
	const quiet = 4
	n := code.Size + 2*quiet
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges" role="img" aria-label="QR code that opens the FTW app"><rect width="%d" height="%d" fill="#fff"/><path fill="#000" d="`, n, n, n, n)
	for y := range code.Size {
		for x := range code.Size {
			if code.Black(x, y) {
				fmt.Fprintf(&b, "M%d %dh1v1h-1z", x+quiet, y+quiet)
			}
		}
	}
	b.WriteString(`"/></svg>`)
	return template.HTML(b.String()) // built here from numbers only
}

const pageStyle = `
:root{--bg:#f6f5f2;--fg:#17181a;--muted:#5d6066;--card:#fff;--line:#e2e0db;--accent:#1f6f4a;--warn:#8a4b00}
@media (prefers-color-scheme:dark){:root{--bg:#111214;--fg:#eceae6;--muted:#a3a6ab;--card:#1b1c1f;--line:#2c2e32;--accent:#5cc28f;--warn:#f0a34a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:560px;margin:0 auto;padding:32px 16px}h1{font-size:1.5rem;line-height:1.25;margin:0 0 8px}h2{font-size:1rem;margin:24px 0 8px}
.muted{color:var(--muted)}.warn{color:var(--warn)}.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px}
ul{margin:0;padding-left:20px}.approve{display:flex;gap:16px;align-items:center;flex-wrap:wrap;margin-top:24px}
.qr{width:232px;height:232px;flex:none;background:#fff;border-radius:8px;padding:4px}.qr svg{width:100%;height:100%}
.code{font:600 1.75rem/1 ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.08em;margin:4px 0 0}
a.button{display:inline-block;background:var(--accent);color:#fff;text-decoration:none;padding:10px 16px;border-radius:8px;font-weight:600}
@media (prefers-color-scheme:dark){a.button{color:#0b1a12}}
button{font:inherit;background:none;border:1px solid var(--line);color:var(--fg);padding:8px 14px;border-radius:8px;cursor:pointer}
#status{margin-top:24px;font-weight:600}
`

var consentTmpl = template.Must(template.New("consent").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connect an assistant · FTW Cloud</title><style nonce="{{.Nonce}}">` + pageStyle + `</style></head>
<body><main id="main" data-rid="{{.RID}}" data-verified="{{.Verified}}">
<h1>Let {{.Name}} into your home?</h1>
<p class="muted">{{if .Verified}}A client FTW Cloud knows, from {{.Host}}.{{else if .FromDocument}}From {{.Host}}. FTW Cloud does not know this client: check the name and the address.{{else}}This name is what the assistant registered with. FTW Cloud has not checked it.{{end}}</p>
<div class="card">
<p>After you approve, this window goes back to <strong>{{.RedirectHost}}</strong>.{{if .Local}} <span class="warn">That is a program on this computer. Approve only if you started it.</span>{{end}}</p>
<h2>It asks to</h2>
<ul>{{range .Scopes}}<li>{{.}}</li>{{end}}</ul>
<p class="muted">{{if .Control}}Control lasts minutes at a time, within limits your box sets. {{end}}It can change nothing lasting by itself. You can remove it at any time, in the FTW app or on your box's own page.</p>
</div>
<div class="approve">
<div class="qr">{{.QR}}</div>
<div>
<p>Approve in the FTW app: scan the QR code with your phone, or open the link.</p>
<p><a class="button" href="{{.Link}}">Open the FTW app</a></p>
<p class="muted">Can't scan or open the link? Type this code in the FTW app, or on your box's own page under Settings, then Access.</p>
<p class="code">{{.Code}}</p>
</div>
</div>
<p id="status" role="status">Waiting for your approval…</p>
<p><a id="back" class="button" hidden>Go back to {{.RedirectHost}}</a></p>
<p><button id="cancel" type="button">Cancel</button></p>
<noscript><p class="warn">This page needs JavaScript to hear your approval.</p></noscript>
</main>
<script nonce="{{.Nonce}}">
(function(){
  var main=document.getElementById('main'), rid=main.dataset.rid, verified=main.dataset.verified==='true';
  var status=document.getElementById('status'), back=document.getElementById('back');
  var es=new EventSource('/oauth/requests/'+encodeURIComponent(rid)+'/events');
  // follow: after the owner acted, go back at once; otherwise a client
  // FTW Cloud does not know gets a link, and the person decides.
  function go(e,text,follow){var d={};try{d=JSON.parse(e.data)}catch(_){}es.close();status.textContent=text;
    if(!d.redirect){return}if(follow||verified){location.replace(d.redirect)}else{back.href=d.redirect;back.hidden=false}}
  es.addEventListener('approved',function(e){go(e,'Approved. Going back…',true)});
  es.addEventListener('denied',function(e){go(e,'Not approved.',true)});
  es.addEventListener('expired',function(e){go(e,'This request ran out. Connect again from the assistant.',false)});
  document.getElementById('cancel').addEventListener('click',function(){
    fetch('/oauth/requests/'+encodeURIComponent(rid)+'/deny',{method:'POST'});
  });
})();
</script>
</body></html>`))

var errorTmpl = template.Must(template.New("error").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connect an assistant · FTW Cloud</title><style nonce="{{.Nonce}}">` + pageStyle + `</style></head>
<body><main><h1>{{.Title}}</h1><p>{{.Text}}</p>
{{if .Back}}<p><a class="button" href="{{.Back}}">Go back to {{.BackHost}}</a></p>{{end}}</main></body></html>`))
