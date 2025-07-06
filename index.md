---
layout: default
title: Home
---
<section class="posts-list">
  {% for post in site.posts %}
    <article class="post-item">
      <h2><a href="{{ post.url | relative_url }}">{{ post.title }}</a></h2>
      <time datetime="{{ post.date | date_to_xmlschema }}">{{ post.date | date: "%B %-d, %Y" }}</time>
      <p>{{ post.excerpt }}</p>
    </article>
  {% endfor %}
</section>
