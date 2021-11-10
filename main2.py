from discord import Client, Embed, Color, Message, Member, TextChannel, Guild, Role, Permissions, utils
from requests import get
from re import findall


def Find(string):
    regex = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"
    url = findall(regex, string)
    return [x[0] for x in url]


def noop():
    pass


client = Client()


@client.event
async def on_ready():
    print('We have logged in as {0.user}'.format(client))

blacklist = ['www.', 'https://', 'http://']


@client.event
async def on_message(message):
    if message.author == client.user:
        return

    if any(word in message.content for word in blacklist):
        print(message.content)
        string = message.content
        url = Find(string)
        print(url)
        VT = 'https://www.virustotal.com/vtapi/v2/url/report'
        params = {
            'apikey': 'key', 'resource': url}
        response = get(VT, params=params)
        positives = response.json()['positives']
        total = response.json()['total']
        scan_date = response.json()['scan_date']
        permalink = response.json()['permalink']
        print(positives)
        print(total)
        print(scan_date)
        print(permalink)

        # malicious embed
        embed_malicious = Embed(
            title="Virus scan result", url=permalink, description="MALICIOUS", color=0xff0000)
        embed_malicious.set_author(name="Link Scanner")
        embed_malicious.set_thumbnail(
            url="https://media.discordapp.net/attachments/720241434850099283/908045512480006224/LAZER_CAT.png")
        embed_malicious.add_field(
            name="Positive:", value=positives, inline=True)
        embed_malicious.add_field(
            name="Negative:", value=total - positives, inline=True)
        embed_malicious.add_field(
            name="Scanned time:", value=scan_date, inline=False)

        # clean embed
        embed_clean = Embed(title="Virus scan result",
                            url=permalink, description="CLEAN", color=0x3dd813)
        embed_clean.set_author(name="Link Scanner")
        embed_clean.set_thumbnail(
            url="https://media.discordapp.net/attachments/720241434850099283/908049931317682256/Orange-tabby-cat-sleeping-with-eyes-closed.png")
        embed_clean.add_field(name="Positive:", value=positives, inline=True)
        embed_clean.add_field(
            name="Negative:", value=total - positives, inline=True)
        embed_clean.add_field(name="Scanned time:",
                              value=scan_date, inline=False)

        if positives >= 3:
            await message.channel.send(embed=embed_malicious)
            await message.delete()
            await message.channel.send("I SEE YOU 👁️ 👁️")
            await message.channel.send("I'm always watching")
        else:
            await message.channel.send(embed=embed_clean)

client.run('token')
