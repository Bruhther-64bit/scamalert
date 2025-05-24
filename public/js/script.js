document.addEventListener("DOMContentLoaded", function () {
  // DOM elements
  const postBtn = document.getElementById("postBtn");
  const postInput = document.getElementById("postInput");
  const postModal = new bootstrap.Modal(document.getElementById("postModal"));
  const postForm = document.getElementById("postForm");
  const postsContainer = document.getElementById("postsContainer");
  const editPostModal = new bootstrap.Modal(document.getElementById("editPostModal"));
  const editPostForm = document.getElementById("editPostForm");

  // Event listeners
  if (postBtn) {
    postBtn.addEventListener("click", () => {
      postModal.show();
    });
  }

  if (postInput) {
    postInput.addEventListener("click", () => {
      postModal.show();
    });
  }

  if (postForm) {
    postForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const content = document.getElementById("postContent").value;

      try {
        const response = await fetch("/posts", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            content,
            userId: typeof currentUserId !== 'undefined' ? currentUserId : null
          }),
        });

        if (response.ok) {
          const data = await response.json();
          addNewPostToDOM(data.post);
          postModal.hide();
          postForm.reset();
        }
      } catch (error) {
        console.error("Error posting:", error);
      }
    });
  }

  // Edit Post
  document.addEventListener('click', async function(e) {
    if (e.target.classList.contains('edit-post') || e.target.closest('.edit-post')) {
      const postElement = e.target.closest('.post');
      const postId = postElement.dataset.postId;
      const postContent = postElement.querySelector('.card-text').textContent;
      
      document.getElementById('editPostId').value = postId;
      document.getElementById('editPostContent').value = postContent;
    }

    // Delete Post
    if (e.target.classList.contains('delete-post') || e.target.closest('.delete-post')) {
      if (!confirm('Are you sure you want to delete this post?')) return;
      
      const postElement = e.target.closest('.post');
      const postId = postElement.dataset.postId;
      
      try {
        const response = await fetch(`/posts/${postId}`, {
          method: 'DELETE',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ userId: typeof currentUserId !== 'undefined' ? currentUserId : null })
        });

        if (response.ok) {
          postElement.remove();
        }
      } catch (error) {
        console.error('Error deleting post:', error);
      }
    }
  });

  // Update Post
  if (editPostForm) {
    editPostForm.addEventListener('submit', async function(e) {
      e.preventDefault();
      
      const postId = document.getElementById('editPostId').value;
      const content = document.getElementById('editPostContent').value;
      
      try {
        const response = await fetch(`/posts/${postId}`, {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ content })
        });

        if (response.ok) {
          const data = await response.json();
          const postElement = document.querySelector(`.post[data-post-id="${postId}"]`);
          if (postElement) {
            postElement.querySelector('.card-text').textContent = data.post.content;
          }
          editPostModal.hide();
        }
      } catch (error) {
        console.error('Error updating post:', error);
      }
    });
  }
  // Add Comment
  document.addEventListener('submit', async function(e) {
    if (e.target.classList.contains('add-comment-form')) {
      e.preventDefault();
      const postId = e.target.dataset.postId;
      const input = e.target.querySelector('input');
      const content = input.value.trim();

      if (!content) return;

      try {
        const response = await fetch(`/posts/${postId}/comments`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            content,
            userId: typeof currentUserId !== 'undefined' ? currentUserId : null
          }),
        });

        if (response.ok) {
          const data = await response.json();
          addCommentToDOM(postId, data.comment);
          input.value = '';
        }
      } catch (error) {
        console.error("Error adding comment:", error);
      }
    }
  });

  // Delete Comment
  document.addEventListener('click', async function(e) {
    if (e.target.classList.contains('delete-comment') || e.target.closest('.delete-comment')) {
      if (!confirm('Are you sure you want to delete this comment?')) return;
      
      const commentElement = e.target.closest('.comment');
      const commentId = commentElement.dataset.commentId;
      const postId = commentElement.closest('.post').dataset.postId;
      
      try {
        const response = await fetch(`/posts/${postId}/comments/${commentId}`, {
          method: 'DELETE',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ 
            userId: typeof currentUserId !== 'undefined' ? currentUserId : null 
          })
        });

        if (response.ok) {
          commentElement.remove();
        }
      } catch (error) {
        console.error('Error deleting comment:', error);
      }
    }
  });

  // Helper function to add new comment to DOM
  function addCommentToDOM(postId, comment) {
    const commentsContainer = document.querySelector(`#comments-${postId}`);
    if (!commentsContainer) return;

    const commentElement = document.createElement('div');
    commentElement.className = 'comment card mt-2 p-2';
    commentElement.dataset.commentId = comment._id;
    commentElement.innerHTML = `
      <div class="d-flex justify-content-between">
        <small class="text-muted">
          ${comment.author ? comment.author.username : 'Anonymous'}:
        </small>
        ${comment.author && comment.author._id.toString() === currentUserId ? `
          <button class="btn btn-sm btn-outline-danger delete-comment">
            <i class="fas fa-trash fa-xs"></i>
          </button>
        ` : ''}
      </div>
      <p class="mb-0">${comment.content}</p>
      <small class="text-muted">
        ${new Date(comment.timestamp).toLocaleString()}
      </small>
    `;

    commentsContainer.appendChild(commentElement);
  }
  // Function to add new post to DOM
  function addNewPostToDOM(post) {
    if (!postsContainer) return;

    const postElement = document.createElement('div');
    postElement.className = 'post card mb-3';
    postElement.dataset.postId = post._id;
    postElement.innerHTML = `
      <div class="card-body">
        <div class="post-actions float-end">
          <button class="btn btn-sm btn-outline-secondary edit-post" data-bs-toggle="modal" data-bs-target="#editPostModal">
            <i class="fas fa-edit"></i>
          </button>
          <button class="btn btn-sm btn-outline-danger delete-post">
            <i class="fas fa-trash"></i>
          </button>
        </div>
        <p class="card-text">${post.content}</p>
        <small class="text-muted">
          Posted by ${post.author ? post.author.username : 'Anonymous'} 
          on ${new Date(post.timestamp).toLocaleString()}
        </small>
      </div>
    `;
    
    // Add to the top of the container
    postsContainer.insertBefore(postElement, postsContainer.firstChild);
  }
});
