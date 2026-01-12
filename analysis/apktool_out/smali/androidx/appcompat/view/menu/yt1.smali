.class public final Landroidx/appcompat/view/menu/yt1;
.super Landroidx/appcompat/view/menu/i82;
.source "SourceFile"


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/k82;)V
    .locals 0

    invoke-direct {p0, p1}, Landroidx/appcompat/view/menu/i82;-><init>(Landroidx/appcompat/view/menu/k82;)V

    return-void
.end method

.method public static bridge synthetic y(Landroidx/appcompat/view/menu/yt1;Ljava/net/HttpURLConnection;)[B
    .locals 0

    invoke-static {p1}, Landroidx/appcompat/view/menu/yt1;->z(Ljava/net/HttpURLConnection;)[B

    move-result-object p0

    return-object p0
.end method

.method private static z(Ljava/net/HttpURLConnection;)[B
    .locals 4

    const/4 v0, 0x0

    :try_start_0
    new-instance v1, Ljava/io/ByteArrayOutputStream;

    invoke-direct {v1}, Ljava/io/ByteArrayOutputStream;-><init>()V

    invoke-virtual {p0}, Ljava/net/URLConnection;->getInputStream()Ljava/io/InputStream;

    move-result-object v0

    const/16 p0, 0x400

    new-array p0, p0, [B

    :goto_0
    invoke-virtual {v0, p0}, Ljava/io/InputStream;->read([B)I

    move-result v2

    if-lez v2, :cond_0

    const/4 v3, 0x0

    invoke-virtual {v1, p0, v3, v2}, Ljava/io/ByteArrayOutputStream;->write([BII)V

    goto :goto_0

    :catchall_0
    move-exception p0

    goto :goto_1

    :cond_0
    invoke-virtual {v1}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B

    move-result-object p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-virtual {v0}, Ljava/io/InputStream;->close()V

    return-object p0

    :goto_1
    if-eqz v0, :cond_1

    invoke-virtual {v0}, Ljava/io/InputStream;->close()V

    :cond_1
    throw p0
.end method


# virtual methods
.method public final A()Z
    .locals 2

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/i82;->u()V

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/bz1;->a()Landroid/content/Context;

    move-result-object v0

    const-string v1, "connectivity"

    invoke-virtual {v0, v1}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/net/ConnectivityManager;

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    :try_start_0
    invoke-virtual {v0}, Landroid/net/ConnectivityManager;->getActiveNetworkInfo()Landroid/net/NetworkInfo;

    move-result-object v1
    :try_end_0
    .catch Ljava/lang/SecurityException; {:try_start_0 .. :try_end_0} :catch_0

    :catch_0
    :cond_0
    if-eqz v1, :cond_1

    invoke-virtual {v1}, Landroid/net/NetworkInfo;->isConnected()Z

    move-result v0

    if-eqz v0, :cond_1

    const/4 v0, 0x1

    return v0

    :cond_1
    const/4 v0, 0x0

    return v0
.end method

.method public final bridge synthetic a()Landroid/content/Context;
    .locals 1

    invoke-super {p0}, Landroidx/appcompat/view/menu/bz1;->a()Landroid/content/Context;

    move-result-object v0

    return-object v0
.end method

.method public final bridge synthetic b()Landroidx/appcompat/view/menu/bc;
    .locals 1

    invoke-super {p0}, Landroidx/appcompat/view/menu/bz1;->b()Landroidx/appcompat/view/menu/bc;

    move-result-object v0

    return-object v0
.end method

.method public final bridge synthetic d()Landroidx/appcompat/view/menu/if1;
    .locals 1

    invoke-super {p0}, Landroidx/appcompat/view/menu/bz1;->d()Landroidx/appcompat/view/menu/if1;

    move-result-object v0

    return-object v0
.end method

.method public final bridge synthetic e()Landroidx/appcompat/view/menu/mf1;
    .locals 1

    invoke-super {p0}, Landroidx/appcompat/view/menu/bz1;->e()Landroidx/appcompat/view/menu/mf1;

    move-result-object v0

    return-object v0
.end method

.method public final bridge synthetic f()Landroidx/appcompat/view/menu/yh1;
    .locals 1

    invoke-super {p0}, Landroidx/appcompat/view/menu/bz1;->f()Landroidx/appcompat/view/menu/yh1;

    move-result-object v0

    return-object v0
.end method

.method public final bridge synthetic g()Landroidx/appcompat/view/menu/it1;
    .locals 1

    invoke-super {p0}, Landroidx/appcompat/view/menu/bz1;->g()Landroidx/appcompat/view/menu/it1;

    move-result-object v0

    return-object v0
.end method

.method public final bridge synthetic h()Landroidx/appcompat/view/menu/fw1;
    .locals 1

    invoke-super {p0}, Landroidx/appcompat/view/menu/bz1;->h()Landroidx/appcompat/view/menu/fw1;

    move-result-object v0

    return-object v0
.end method

.method public final bridge synthetic i()Landroidx/appcompat/view/menu/pu1;
    .locals 1

    invoke-super {p0}, Landroidx/appcompat/view/menu/bz1;->i()Landroidx/appcompat/view/menu/pu1;

    move-result-object v0

    return-object v0
.end method

.method public final bridge synthetic j()Landroidx/appcompat/view/menu/t92;
    .locals 1

    invoke-super {p0}, Landroidx/appcompat/view/menu/bz1;->j()Landroidx/appcompat/view/menu/t92;

    move-result-object v0

    return-object v0
.end method

.method public final bridge synthetic k()V
    .locals 0

    invoke-super {p0}, Landroidx/appcompat/view/menu/bz1;->k()V

    return-void
.end method

.method public final bridge synthetic l()Landroidx/appcompat/view/menu/lt1;
    .locals 1

    invoke-super {p0}, Landroidx/appcompat/view/menu/bz1;->l()Landroidx/appcompat/view/menu/lt1;

    move-result-object v0

    return-object v0
.end method

.method public final bridge synthetic m()V
    .locals 0

    invoke-super {p0}, Landroidx/appcompat/view/menu/bz1;->m()V

    return-void
.end method

.method public final bridge synthetic n()V
    .locals 0

    invoke-super {p0}, Landroidx/appcompat/view/menu/bz1;->n()V

    return-void
.end method

.method public final bridge synthetic o()Landroidx/appcompat/view/menu/e92;
    .locals 1

    invoke-super {p0}, Landroidx/appcompat/view/menu/c82;->o()Landroidx/appcompat/view/menu/e92;

    move-result-object v0

    return-object v0
.end method

.method public final bridge synthetic p()Landroidx/appcompat/view/menu/se2;
    .locals 1

    invoke-super {p0}, Landroidx/appcompat/view/menu/c82;->p()Landroidx/appcompat/view/menu/se2;

    move-result-object v0

    return-object v0
.end method

.method public final bridge synthetic q()Landroidx/appcompat/view/menu/hg1;
    .locals 1

    invoke-super {p0}, Landroidx/appcompat/view/menu/c82;->q()Landroidx/appcompat/view/menu/hg1;

    move-result-object v0

    return-object v0
.end method

.method public final bridge synthetic r()Landroidx/appcompat/view/menu/nv1;
    .locals 1

    invoke-super {p0}, Landroidx/appcompat/view/menu/c82;->r()Landroidx/appcompat/view/menu/nv1;

    move-result-object v0

    return-object v0
.end method

.method public final bridge synthetic s()Landroidx/appcompat/view/menu/l62;
    .locals 1

    invoke-super {p0}, Landroidx/appcompat/view/menu/c82;->s()Landroidx/appcompat/view/menu/l62;

    move-result-object v0

    return-object v0
.end method

.method public final bridge synthetic t()Landroidx/appcompat/view/menu/g82;
    .locals 1

    invoke-super {p0}, Landroidx/appcompat/view/menu/c82;->t()Landroidx/appcompat/view/menu/g82;

    move-result-object v0

    return-object v0
.end method

.method public final x()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method
