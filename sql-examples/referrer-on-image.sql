SELECT year(e.dt) YR, month(e.dt) MO, day(e.dt) DAY, ua.value USER_AGENT, ref.value REFERRER
FROM entries e INNER JOIN vhost ON e.id_vhost = vhost.id
INNER JOIN url ON e.id_url = url.id
INNER JOIN ua ON e.id_ua = ua.id
INNER JOIN ref ON e.id_ref = ref.id
WHERE vhost.value REGEXP '(www\.)?edsuom.com'
 AND url.value = '/pics/hominim-skull.jpg'
 AND e.http != 404
ORDER BY YR DESC, MO DESC, DAY DESC


