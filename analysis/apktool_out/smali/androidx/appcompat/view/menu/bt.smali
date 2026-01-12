.class public abstract synthetic Landroidx/appcompat/view/menu/bt;
.super Ljava/lang/Object;
.source "SourceFile"


# direct methods
.method public static final a(Landroidx/appcompat/view/menu/jh;)V
    .locals 2

    sget-object v0, Landroidx/appcompat/view/menu/n60;->d:Landroidx/appcompat/view/menu/n60$b;

    invoke-interface {p0, v0}, Landroidx/appcompat/view/menu/jh;->d(Landroidx/appcompat/view/menu/jh$c;)Landroidx/appcompat/view/menu/jh$b;

    move-result-object v0

    if-nez v0, :cond_0

    return-void

    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const-string v1, "Flow context cannot contain job in it. Had "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    new-instance v0, Ljava/lang/IllegalArgumentException;

    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public static final b(Landroidx/appcompat/view/menu/ws;Landroidx/appcompat/view/menu/jh;)Landroidx/appcompat/view/menu/ws;
    .locals 8

    invoke-static {p1}, Landroidx/appcompat/view/menu/bt;->a(Landroidx/appcompat/view/menu/jh;)V

    sget-object v0, Landroidx/appcompat/view/menu/ao;->m:Landroidx/appcompat/view/menu/ao;

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->a(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    instance-of v0, p0, Landroidx/appcompat/view/menu/kx;

    if-eqz v0, :cond_1

    move-object v1, p0

    check-cast v1, Landroidx/appcompat/view/menu/kx;

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x6

    const/4 v6, 0x0

    move-object v2, p1

    invoke-static/range {v1 .. v6}, Landroidx/appcompat/view/menu/kx$a;->a(Landroidx/appcompat/view/menu/kx;Landroidx/appcompat/view/menu/jh;ILandroidx/appcompat/view/menu/t8;ILjava/lang/Object;)Landroidx/appcompat/view/menu/ws;

    move-result-object p0

    goto :goto_0

    :cond_1
    new-instance v7, Landroidx/appcompat/view/menu/xa;

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/16 v5, 0xc

    const/4 v6, 0x0

    move-object v0, v7

    move-object v1, p0

    move-object v2, p1

    invoke-direct/range {v0 .. v6}, Landroidx/appcompat/view/menu/xa;-><init>(Landroidx/appcompat/view/menu/ws;Landroidx/appcompat/view/menu/jh;ILandroidx/appcompat/view/menu/t8;ILandroidx/appcompat/view/menu/kj;)V

    move-object p0, v7

    :goto_0
    return-object p0
.end method
