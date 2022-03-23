package telran.java41.forum.service;

import java.util.List;

import telran.java41.forum.dto.DatePeriodDto;
import telran.java41.forum.dto.NewCommentDto;
import telran.java41.forum.dto.NewPostDto;
import telran.java41.forum.dto.PostDto;

public interface ForumService {
	PostDto addNewPost(NewPostDto newPost, String author);

	PostDto getPost(String id);

	PostDto removePost(String id);

	PostDto updatePost(NewPostDto postUpdateDto, String id);

	void addLike(String id);

	PostDto addComment(String id, String author, NewCommentDto newCommentDto);

	Iterable<PostDto> findPostsByAuthor(String author);

	Iterable<PostDto> findPostsByTags(List<String> tags);

	Iterable<PostDto> findPostsByDates(DatePeriodDto datePeriodDto);
}
