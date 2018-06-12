/* Who is direct linking to images on your site?
*/
SELECT
 year(e.dt) YR,
 month(e.dt) MO,
 e.ip IP,
 vhost.value VHOST,
 url.value URL,
 e.was_rd RD,
 ref.value REFERRER
FROM entries e
INNER JOIN vhost ON vhost.id = e.id_vhost
INNER JOIN url ON url.id = e.id_url
INNER JOIN ref ON ref.id = e.id_ref
WHERE datediff(now(), e.dt) < 10
 AND e.http between 200 and 300
 AND url.value NOT REGEXP '\.(jpe?g|gif|png|ico|txt|css|ttf|woff|eot.)$' 
ORDER BY VHOST ASC, e.dt DESC;


