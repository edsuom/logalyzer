SELECT *
FROM entries e INNER JOIN vhost ON e.id_vhost = vhost.id
INNER JOIN url ON e.id_url = url.id
WHERE vhost.value REGEXP '(www\.)?tellectual.com'
 AND url.value REGEXP 'uthors\.html$'
 AND year(e.dt) = 2016

