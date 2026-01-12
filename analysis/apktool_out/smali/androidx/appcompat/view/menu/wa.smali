.class public abstract Landroidx/appcompat/view/menu/wa;
.super Landroidx/appcompat/view/menu/ta;
.source "SourceFile"


# instance fields
.field public final d:Landroidx/appcompat/view/menu/ws;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/ws;Landroidx/appcompat/view/menu/jh;ILandroidx/appcompat/view/menu/t8;)V
    .locals 0

    invoke-direct {p0, p2, p3, p4}, Landroidx/appcompat/view/menu/ta;-><init>(Landroidx/appcompat/view/menu/jh;ILandroidx/appcompat/view/menu/t8;)V

    iput-object p1, p0, Landroidx/appcompat/view/menu/wa;->d:Landroidx/appcompat/view/menu/ws;

    return-void
.end method

.method public static synthetic j(Landroidx/appcompat/view/menu/wa;Landroidx/appcompat/view/menu/xs;Landroidx/appcompat/view/menu/wg;)Ljava/lang/Object;
    .locals 4

    iget v0, p0, Landroidx/appcompat/view/menu/ta;->b:I

    const/4 v1, -0x3

    if-ne v0, v1, :cond_3

    invoke-interface {p2}, Landroidx/appcompat/view/menu/wg;->b()Landroidx/appcompat/view/menu/jh;

    move-result-object v0

    iget-object v1, p0, Landroidx/appcompat/view/menu/ta;->a:Landroidx/appcompat/view/menu/jh;

    invoke-interface {v0, v1}, Landroidx/appcompat/view/menu/jh;->o(Landroidx/appcompat/view/menu/jh;)Landroidx/appcompat/view/menu/jh;

    move-result-object v1

    invoke-static {v1, v0}, Landroidx/appcompat/view/menu/x50;->a(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_1

    invoke-virtual {p0, p1, p2}, Landroidx/appcompat/view/menu/wa;->m(Landroidx/appcompat/view/menu/xs;Landroidx/appcompat/view/menu/wg;)Ljava/lang/Object;

    move-result-object p0

    invoke-static {}, Landroidx/appcompat/view/menu/y50;->c()Ljava/lang/Object;

    move-result-object p1

    if-ne p0, p1, :cond_0

    return-object p0

    :cond_0
    sget-object p0, Landroidx/appcompat/view/menu/n31;->a:Landroidx/appcompat/view/menu/n31;

    return-object p0

    :cond_1
    sget-object v2, Landroidx/appcompat/view/menu/zg;->b:Landroidx/appcompat/view/menu/zg$b;

    invoke-interface {v1, v2}, Landroidx/appcompat/view/menu/jh;->d(Landroidx/appcompat/view/menu/jh$c;)Landroidx/appcompat/view/menu/jh$b;

    move-result-object v3

    invoke-interface {v0, v2}, Landroidx/appcompat/view/menu/jh;->d(Landroidx/appcompat/view/menu/jh$c;)Landroidx/appcompat/view/menu/jh$b;

    move-result-object v0

    invoke-static {v3, v0}, Landroidx/appcompat/view/menu/x50;->a(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_3

    invoke-virtual {p0, p1, v1, p2}, Landroidx/appcompat/view/menu/wa;->l(Landroidx/appcompat/view/menu/xs;Landroidx/appcompat/view/menu/jh;Landroidx/appcompat/view/menu/wg;)Ljava/lang/Object;

    move-result-object p0

    invoke-static {}, Landroidx/appcompat/view/menu/y50;->c()Ljava/lang/Object;

    move-result-object p1

    if-ne p0, p1, :cond_2

    return-object p0

    :cond_2
    sget-object p0, Landroidx/appcompat/view/menu/n31;->a:Landroidx/appcompat/view/menu/n31;

    return-object p0

    :cond_3
    invoke-super {p0, p1, p2}, Landroidx/appcompat/view/menu/ta;->b(Landroidx/appcompat/view/menu/xs;Landroidx/appcompat/view/menu/wg;)Ljava/lang/Object;

    move-result-object p0

    invoke-static {}, Landroidx/appcompat/view/menu/y50;->c()Ljava/lang/Object;

    move-result-object p1

    if-ne p0, p1, :cond_4

    return-object p0

    :cond_4
    sget-object p0, Landroidx/appcompat/view/menu/n31;->a:Landroidx/appcompat/view/menu/n31;

    return-object p0
.end method

.method public static synthetic k(Landroidx/appcompat/view/menu/wa;Landroidx/appcompat/view/menu/ck0;Landroidx/appcompat/view/menu/wg;)Ljava/lang/Object;
    .locals 1

    new-instance v0, Landroidx/appcompat/view/menu/ks0;

    invoke-direct {v0, p1}, Landroidx/appcompat/view/menu/ks0;-><init>(Landroidx/appcompat/view/menu/hs0;)V

    invoke-virtual {p0, v0, p2}, Landroidx/appcompat/view/menu/wa;->m(Landroidx/appcompat/view/menu/xs;Landroidx/appcompat/view/menu/wg;)Ljava/lang/Object;

    move-result-object p0

    invoke-static {}, Landroidx/appcompat/view/menu/y50;->c()Ljava/lang/Object;

    move-result-object p1

    if-ne p0, p1, :cond_0

    return-object p0

    :cond_0
    sget-object p0, Landroidx/appcompat/view/menu/n31;->a:Landroidx/appcompat/view/menu/n31;

    return-object p0
.end method


# virtual methods
.method public b(Landroidx/appcompat/view/menu/xs;Landroidx/appcompat/view/menu/wg;)Ljava/lang/Object;
    .locals 0

    invoke-static {p0, p1, p2}, Landroidx/appcompat/view/menu/wa;->j(Landroidx/appcompat/view/menu/wa;Landroidx/appcompat/view/menu/xs;Landroidx/appcompat/view/menu/wg;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public e(Landroidx/appcompat/view/menu/ck0;Landroidx/appcompat/view/menu/wg;)Ljava/lang/Object;
    .locals 0

    invoke-static {p0, p1, p2}, Landroidx/appcompat/view/menu/wa;->k(Landroidx/appcompat/view/menu/wa;Landroidx/appcompat/view/menu/ck0;Landroidx/appcompat/view/menu/wg;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final l(Landroidx/appcompat/view/menu/xs;Landroidx/appcompat/view/menu/jh;Landroidx/appcompat/view/menu/wg;)Ljava/lang/Object;
    .locals 8

    invoke-interface {p3}, Landroidx/appcompat/view/menu/wg;->b()Landroidx/appcompat/view/menu/jh;

    move-result-object v0

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/va;->a(Landroidx/appcompat/view/menu/xs;Landroidx/appcompat/view/menu/jh;)Landroidx/appcompat/view/menu/xs;

    move-result-object v2

    const/4 v3, 0x0

    new-instance v4, Landroidx/appcompat/view/menu/wa$a;

    const/4 p1, 0x0

    invoke-direct {v4, p0, p1}, Landroidx/appcompat/view/menu/wa$a;-><init>(Landroidx/appcompat/view/menu/wa;Landroidx/appcompat/view/menu/wg;)V

    const/4 v6, 0x4

    const/4 v7, 0x0

    move-object v1, p2

    move-object v5, p3

    invoke-static/range {v1 .. v7}, Landroidx/appcompat/view/menu/va;->c(Landroidx/appcompat/view/menu/jh;Ljava/lang/Object;Ljava/lang/Object;Landroidx/appcompat/view/menu/xw;Landroidx/appcompat/view/menu/wg;ILjava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    invoke-static {}, Landroidx/appcompat/view/menu/y50;->c()Ljava/lang/Object;

    move-result-object p2

    if-ne p1, p2, :cond_0

    return-object p1

    :cond_0
    sget-object p1, Landroidx/appcompat/view/menu/n31;->a:Landroidx/appcompat/view/menu/n31;

    return-object p1
.end method

.method public abstract m(Landroidx/appcompat/view/menu/xs;Landroidx/appcompat/view/menu/wg;)Ljava/lang/Object;
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    iget-object v1, p0, Landroidx/appcompat/view/menu/wa;->d:Landroidx/appcompat/view/menu/ws;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, " -> "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-super {p0}, Landroidx/appcompat/view/menu/ta;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
