# XS-Search/XS-Leaks - Html Reinjection And Defenses

## With HTML or Re Injection


Here you can find techniques to exfiltrate information from a cross-origin HTML **injecting HTML content**. These techniques are interesting in cases where for any reason you can **inject HTML but you cannot inject JS code**.

### Dangling Markup

### Image Lazy Loading

If you need to **exfiltrate content** and you can **add HTML previous to the secret** you should check the **common dangling markup techniques**.\
However, if for whatever reason you **MUST** do it **char by char** (maybe the communication is via a cache hit) you can use this trick.

**Images** in HTML has a "**loading**" attribute whose value can be "**lazy**". In that case, the image will be loaded when it's viewed and not while the page is loading:

```html
<img src=/something loading=lazy >
```

Therefore, what you can do is to **add a lot of junk chars** (For example **thousands of "W"s**) to **fill the web page before the secret or add something like** `<br><canvas height="1850px"></canvas><br>.`\
Then if for example our **injection appear before the flag**, the **image** would be **loaded**, but if appears **after** the **flag**, the flag + the junk will **prevent it from being loaded** (you will need to play with how much junk to place). This is what happened in [**this writeup**](https://blog.huli.tw/2022/10/08/en/sekaictf2022-safelist-and-connection/).

Another option would be to use the **scroll-to-text-fragment** if allowed:

#### Scroll-to-text-fragment

However, you make the **bot access the page** with something like

```
#:~:text=SECR
```

So the web page will be something like: **`https://victim.com/post.html#:~:text=SECR`**

Where post.html contains the attacker junk chars and lazy load image and then the secret of the bot is added.

What this text will do is to make the bot access any text in the page that contains the text `SECR`. As that text is the secret and it's just **below the image**, the **image will only load if the guessed secret is correct**. So there you have your oracle to **exfiltrate the secret char by char**.

Some code example to exploit this: [https://gist.github.com/jorgectf/993d02bdadb5313f48cf1dc92a7af87e](https://gist.github.com/jorgectf/993d02bdadb5313f48cf1dc92a7af87e)

### Image Lazy Loading Time Based

If it's **not possible to load an external image** that could indicate the attacker that the image was loaded, another option would be to try to **guess the char several times and measure that**. If the image is loaded all the requests would take longer that if the image isn't loaded. This is what was used in the [**solution of this writeup**](https://blog.huli.tw/2022/10/08/en/sekaictf2022-safelist-and-connection/) **sumarized here:**

### ReDoS

### CSS ReDoS

If `jQuery(location.hash)` is used, it's possible to find out via timing i**f some HTML content exists**, this is because if the selector `main[id='site-main']` doesn't match it doesn't need to check the rest of the **selectors**:

```javascript
$(
  "*:has(*:has(*:has(*)) *:has(*:has(*:has(*))) *:has(*:has(*:has(*)))) main[id='site-main']"
)
```

### CSS Injection


## Defenses


There are mitigations recommended in [https://xsinator.com/paper.pdf](https://xsinator.com/paper.pdf) also in each section of the wiki [https://xsleaks.dev/](https://xsleaks.dev/). Take a look there for more information about how to protect against these techniques.


## References


- [https://xsinator.com/paper.pdf](https://xsinator.com/paper.pdf)
- [https://xsleaks.dev/](https://xsleaks.dev)
- [https://github.com/xsleaks/xsleaks](https://github.com/xsleaks/xsleaks)
- [https://xsinator.com/](https://xsinator.com/)
- [https://github.com/ka0labs/ctf-writeups/tree/master/2019/nn9ed/x-oracle](https://github.com/ka0labs/ctf-writeups/tree/master/2019/nn9ed/x-oracle)
