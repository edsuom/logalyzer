SELECT year(e.dt) YR, month(e.dt) MO, count(distinct(e.ip)) N, vhost.value VHOST, url.value URL
FROM entries e INNER JOIN vhost ON e.id_vhost = vhost.id
INNER JOIN url ON e.id_url = url.id
WHERE url.value REGEXP '\.html$'
 AND e.http != 404
 AND datediff(now(), e.dt) < 366
GROUP BY YR, MO, VHOST, URL
HAVING N > 5
ORDER BY VHOST, YR DESC, MO DESC, N DESC;


