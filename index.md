---
layout: default
title: Home
---

<section class="posts-grid">
  {% for post in site.posts %}
    <article class="post-card">
      <div class="post-card-meta">
        <time datetime="{{ post.date | date_to_xmlschema }}">
          {{ post.date | date: "%b %-d, %Y" }}
        </time>
        {% for cat in post.categories %}
          <span class="post-tag">{{ cat }}</span>
        {% endfor %}
      </div>
      <h2>
        <a href="{{ post.url | relative_url }}">{{ post.title }}</a>
      </h2>
      <p class="excerpt">{{ post.description | strip_html | truncate: 160 }}</p>
    </article>
  {% endfor %}
</section>
