---
layout: default
title: Home
---

<div class="layout">

  <!-- SIDEBAR -------------------------------------------------->
  <aside class="sidebar">
    <img src="https://avatars.githubusercontent.com/u/143962203?v=4"
         alt="Profile picture" class="profile-pic">

    <h3 class="author-name">{{ site.author.name }}</h3>
    <p class="location">Italia 🇮🇹</p>
    <p class="bio">{{ site.author.bio }}</p>

    <div class="social">
      <a href="https://www.linkedin.com/in/martino-spagnuolo/"
         target="_blank" rel="noopener">LinkedIn</a>
    </div>
  </aside>

  <!-- POST GRID ----------------------------------------------->
  <section class="posts-grid">
    {% for post in site.posts %}
      <article class="post-card">
        <h2>
          <a href="{{ post.url | relative_url }}">{{ post.title }}</a>
        </h2>

        <p class="excerpt">
          {{ post.description | strip_html }}
        </p>

        <a class="read-more" href="{{ post.url | relative_url }}">Read more »</a>
      </article>
    {% endfor %}
  </section>

</div>
