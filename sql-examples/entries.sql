select e.dt DT, e.ip IP, e.http, e.was_rd RD, vhost.value VHOST, url.value URL, left(ref.value, 80) REF, left(ua.value, 80) UA
from entries e
inner join vhost on e.id_vhost = vhost.id
inner join url on e.id_url = url.id
inner join ua on e.id_ua = ua.id
inner join ref on e.id_ref = ref.id
where e.http != 404 and url.value not regexp '\.(css|ico)$'
order by DT desc, e.id desc
limit 1000;


