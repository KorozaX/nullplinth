JSON.stringify({
  clientWidth: document.documentElement.clientWidth,
  scrollWidth: document.documentElement.scrollWidth,
  innerWidth: window.innerWidth,
  bodyScrollWidth: document.body.scrollWidth,
  offenders: Array.from(document.querySelectorAll('*'))
    .map(function (el) { return { tag: el.tagName, cls: String(el.className || '').slice(0, 48), right: Math.round(el.getBoundingClientRect().right), width: Math.round(el.getBoundingClientRect().width) }; })
    .filter(function (o) { return o.right > window.innerWidth + 1; })
    .sort(function (a, b) { return b.right - a.right; })
    .slice(0, 10)
})