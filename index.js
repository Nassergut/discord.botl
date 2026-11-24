require("dotenv").config();
const {
  Client, GatewayIntentBits, Partials, PermissionsBitField,
  AuditLogEvent, EmbedBuilder
} = require("discord.js");

const token = process.env.DISCORD_TOKEN;
if (!token) {
  console.error("Missing DISCORD_TOKEN. Copy .env.example to .env and add your bot token.");
  process.exit(1);
}

const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMembers,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent
  ],
  partials: [Partials.Channel, Partials.Message]
});

const owners = new Set((process.env.OWNER_IDS || "").split(",").map(x => x.trim()).filter(Boolean));
const spamThreshold = Math.max(3, Number(process.env.SPAM_THRESHOLD || 6));
const nukeThreshold = Math.max(2, Number(process.env.NUKE_THRESHOLD || 2));
const LOG_CHANNEL_ID = process.env.LOG_CHANNEL_ID || "";
const messageHits = new Map();
const destructiveHits = new Map();
const recentJoins = new Map();
const warned = new Set();

async function log(guild, title, description, color = 0x5865F2) {
  try {
    const channel = LOG_CHANNEL_ID
      ? await guild.channels.fetch(LOG_CHANNEL_ID).catch(() => null)
      : guild.channels.cache.find(c => c.isTextBased() && c.name === "security-logs");
    if (!channel || !channel.isTextBased()) return;
    await channel.send({ embeds: [new EmbedBuilder().setColor(color).setTitle(title).setDescription(description).setTimestamp()] });
  } catch {}
}

function trusted(member) {
  return Boolean(member && (member.id === member.guild.ownerId || owners.has(member.id)));
}

async function punish(member, reason) {
  if (!member || trusted(member) || !member.manageable) return;
  try {
    await member.timeout(10 * 60 * 1000, reason);
    await log(member.guild, "إجراء حماية", `تم إسكات ${member.user.tag}\nالسبب: ${reason}`, 0xED4245);
  } catch (e) {
    await log(member.guild, "تعذر تنفيذ إجراء", `على ${member.user.tag}: ${e.message}`, 0xED4245);
  }
}

client.once("ready", () => {
  console.log(`Logged in as ${client.user.tag}`);
  client.user.setActivity("حماية شــبــاب يـــمــبـــع");
});

client.on("messageCreate", async message => {
  if (!message.guild || message.author.bot || !message.member) return;

  // Block common invite links. Adjust this list to your server rules.
  const invite = /(discord\.gg\/|discord(?:app)?\.com\/invite\/)/i.test(message.content);
  if (invite && !trusted(message.member) && !message.member.permissions.has(PermissionsBitField.Flags.ManageMessages)) {
    await message.delete().catch(() => {});
    await log(message.guild, "رابط دعوة محذوف", `العضو: ${message.author.tag}`, 0xED4245);
    return;
  }

  const now = Date.now();
  const key = `${message.guild.id}:${message.author.id}`;
  const hits = (messageHits.get(key) || []).filter(t => now - t < 7000);
  hits.push(now);
  messageHits.set(key, hits);

  if (hits.length >= spamThreshold && !trusted(message.member)) {
    await punish(message.member, "Anti-Spam: رسائل كثيرة خلال وقت قصير");
    await message.delete().catch(() => {});
    messageHits.set(key, []);
  }
});

client.on("guildMemberAdd", async member => {
  const now = Date.now();
  const hits = (recentJoins.get(member.guild.id) || []).filter(t => now - t < 15000);
  hits.push(now);
  recentJoins.set(member.guild.id, hits);
  if (hits.length >= 10) {
    await log(member.guild, "تنبيه دخول جماعي", `دخل ${hits.length} أعضاء خلال 15 ثانية. راجع قائمة الأعضاء وفعّل التحقق الإضافي في إعدادات Discord.`, 0xFEE75C);
  }
});

async function checkDestructiveAction(guild, type, targetName) {
  try {
    const logs = await guild.fetchAuditLogs({ type, limit: 1 });
    const entry = logs.entries.first();
    if (!entry || Date.now() - entry.createdTimestamp > 8000 || !entry.executor) return;

    const executor = await guild.members.fetch(entry.executor.id).catch(() => null);
    if (!executor || trusted(executor)) return;

    const key = `${guild.id}:${executor.id}`;
    const hits = (destructiveHits.get(key) || []).filter(t => Date.now() - t < 10000);
    hits.push(Date.now());
    destructiveHits.set(key, hits);

    await log(guild, "مراقبة العمليات الحساسة",
      `${executor.user.tag} نفّذ عملية: ${targetName}\nعدد العمليات خلال 10 ثوانٍ: ${hits.length}`, 0xFEE75C);

    if (hits.length >= nukeThreshold && executor.bannable) {
      await executor.ban({ reason: "Anti-Nuke: عمليات حذف متكررة غير مصرح بها" }).catch(() => {});
      await log(guild, "تم إيقاف محاولة تخريب", `تم حظر ${executor.user.tag} بعد عمليات حذف متكررة.`, 0xED4245);
      destructiveHits.set(key, []);
    }
  } catch (e) {
    console.error("Audit log check failed:", e.message);
  }
}

client.on("channelDelete", channel => {
  if (channel.guild) checkDestructiveAction(channel.guild, AuditLogEvent.ChannelDelete, `حذف روم: ${channel.name}`);
});
client.on("roleDelete", role => {
  checkDestructiveAction(role.guild, AuditLogEvent.RoleDelete, `حذف رتبة: ${role.name}`);
});

client.on("guildMemberRemove", async member => {
  // Log departures for visibility; Discord audit logs can be delayed.
  await log(member.guild, "مغادرة عضو", `غادر السيرفر: ${member.user.tag}`);
});

client.on("guildCreate", guild => log(guild, "تمت إضافة البوت", "بوت شــبــاب يـــمــبـــع جاهز للمراقبة."));

client.on("interactionCreate", async interaction => {
  if (!interaction.isChatInputCommand()) return;
  if (interaction.commandName === "security") {
    if (!interaction.memberPermissions?.has(PermissionsBitField.Flags.Administrator) && !owners.has(interaction.user.id)) {
      return interaction.reply({ content: "هذا الأمر للمشرفين فقط.", ephemeral: true });
    }
    return interaction.reply({
      content: [
        "**حالة الحماية**",
        "Anti-Spam: يعمل",
        "منع روابط دعوات Discord: يعمل",
        "Anti-Raid: تنبيه عند الدخول الجماعي",
        "Anti-Nuke: مراقبة حذف الرومات والرتب",
        "سجلات الحماية: قناة security-logs أو LOG_CHANNEL_ID"
      ].join("\n"),
      ephemeral: true
    });
  }
});

client.login(token);
