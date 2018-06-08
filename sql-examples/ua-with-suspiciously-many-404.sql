SELECT count(distinct e.id_url) N, ua.value UA
FROM entries e
INNER JOIN ua ON e.id_ua = ua.id
INNER JOIN url on e.id_url = url.id
WHERE e.http = 404 and url.value not like '/favicon%' and url.value not like '/apple-%'
GROUP BY UA
HAVING N > 2
ORDER BY N DESC;


