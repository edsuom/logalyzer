/* Who is really hammering away at non-existent URLs? Find them and block them,
   by IP address or, more efficiently, finding what URLs hackers are trying for
   and adding a rule to hackers.url.
*/
SELECT count(distinct(e.ip)) N, url.value URL
FROM entries e INNER JOIN vhost ON e.id_vhost = vhost.id
INNER JOIN url ON e.id_url = url.id
WHERE 
 e.http = 404 AND url.value NOT REGEXP '^/(apple|favicon)'
 GROUP BY URL
 HAVING N > 1
ORDER BY N DESC, URL


