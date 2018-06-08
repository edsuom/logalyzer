SELECT count(distinct(e.ip)) N, vhost.value VHOST
FROM entries e INNER JOIN vhost ON e.id_vhost = vhost.id
GROUP BY VHOST
ORDER BY N DESC;

