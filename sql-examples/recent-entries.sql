/* Run this once in a while to see what scumbags are trying to hit your system
   and getting past the hackers.url filter.
*/
select
e.dt DT,
e.ip IP,
e.http,
left(vhost.value, 40) VHOST,
left(url.value, 60) URL,
left(ua.value, 60) UA,
left(ref.value, 60) REF
from entries e
inner join vhost on e.id_vhost = vhost.id
inner join url on e.id_url = url.id
inner join ua on e.id_ua = ua.id
inner join ref on e.id_ref = ref.id
order by DT desc, e.id desc
limit 1000;

