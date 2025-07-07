---
layout: default
title: Home
---
<section class="posts-list">
  {% for post in site.posts %}
    <article class="post-item">
      <h2><a href="{{ post.url | relative_url }}">{{ post.title }}</a></h2>
      <p class="excerpt">{{ post.description | strip_html }}</p>
      <a href="{{ post.url | relative_url }}">Read more &raquo;</a>
    </article>
  {% endfor %}
</section>
