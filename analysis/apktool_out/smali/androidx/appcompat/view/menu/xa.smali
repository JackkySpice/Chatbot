.class public final Landroidx/appcompat/view/menu/xa;
.super Landroidx/appcompat/view/menu/wa;
.source "SourceFile"


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/ws;Landroidx/appcompat/view/menu/jh;ILandroidx/appcompat/view/menu/t8;)V
    .locals 0

    .line 4
    invoke-direct {p0, p1, p2, p3, p4}, Landroidx/appcompat/view/menu/wa;-><init>(Landroidx/appcompat/view/menu/ws;Landroidx/appcompat/view/menu/jh;ILandroidx/appcompat/view/menu/t8;)V

    return-void
.end method

.method public synthetic constructor <init>(Landroidx/appcompat/view/menu/ws;Landroidx/appcompat/view/menu/jh;ILandroidx/appcompat/view/menu/t8;ILandroidx/appcompat/view/menu/kj;)V
    .locals 0

    and-int/lit8 p6, p5, 0x2

    if-eqz p6, :cond_0

    .line 1
    sget-object p2, Landroidx/appcompat/view/menu/ao;->m:Landroidx/appcompat/view/menu/ao;

    :cond_0
    and-int/lit8 p6, p5, 0x4

    if-eqz p6, :cond_1

    const/4 p3, -0x3

    :cond_1
    and-int/lit8 p5, p5, 0x8

    if-eqz p5, :cond_2

    .line 2
    sget-object p4, Landroidx/appcompat/view/menu/t8;->m:Landroidx/appcompat/view/menu/t8;

    .line 3
    :cond_2
    invoke-direct {p0, p1, p2, p3, p4}, Landroidx/appcompat/view/menu/xa;-><init>(Landroidx/appcompat/view/menu/ws;Landroidx/appcompat/view/menu/jh;ILandroidx/appcompat/view/menu/t8;)V

    return-void
.end method


# virtual methods
.method public f(Landroidx/appcompat/view/menu/jh;ILandroidx/appcompat/view/menu/t8;)Landroidx/appcompat/view/menu/ta;
    .locals 2

    new-instance v0, Landroidx/appcompat/view/menu/xa;

    iget-object v1, p0, Landroidx/appcompat/view/menu/wa;->d:Landroidx/appcompat/view/menu/ws;

    invoke-direct {v0, v1, p1, p2, p3}, Landroidx/appcompat/view/menu/xa;-><init>(Landroidx/appcompat/view/menu/ws;Landroidx/appcompat/view/menu/jh;ILandroidx/appcompat/view/menu/t8;)V

    return-object v0
.end method

.method public m(Landroidx/appcompat/view/menu/xs;Landroidx/appcompat/view/menu/wg;)Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/wa;->d:Landroidx/appcompat/view/menu/ws;

    invoke-interface {v0, p1, p2}, Landroidx/appcompat/view/menu/ws;->b(Landroidx/appcompat/view/menu/xs;Landroidx/appcompat/view/menu/wg;)Ljava/lang/Object;

    move-result-object p1

    invoke-static {}, Landroidx/appcompat/view/menu/y50;->c()Ljava/lang/Object;

    move-result-object p2

    if-ne p1, p2, :cond_0

    return-object p1

    :cond_0
    sget-object p1, Landroidx/appcompat/view/menu/n31;->a:Landroidx/appcompat/view/menu/n31;

    return-object p1
.end method
