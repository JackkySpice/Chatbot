.class public final Landroidx/appcompat/view/menu/ks1$a;
.super Landroidx/appcompat/view/menu/m02$b;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/w32;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/view/menu/ks1;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "a"
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-static {}, Landroidx/appcompat/view/menu/ks1;->K()Landroidx/appcompat/view/menu/ks1;

    move-result-object v0

    invoke-direct {p0, v0}, Landroidx/appcompat/view/menu/m02$b;-><init>(Landroidx/appcompat/view/menu/m02;)V

    return-void
.end method

.method public synthetic constructor <init>(Landroidx/appcompat/view/menu/bs1;)V
    .locals 0

    .line 2
    invoke-direct {p0}, Landroidx/appcompat/view/menu/ks1$a;-><init>()V

    return-void
.end method


# virtual methods
.method public final r()I
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/m02$b;->n:Landroidx/appcompat/view/menu/m02;

    check-cast v0, Landroidx/appcompat/view/menu/ks1;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/ks1;->j()I

    move-result v0

    return v0
.end method

.method public final s(Landroidx/appcompat/view/menu/ls1$a;)Landroidx/appcompat/view/menu/ks1$a;
    .locals 1

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/m02$b;->n()V

    iget-object v0, p0, Landroidx/appcompat/view/menu/m02$b;->n:Landroidx/appcompat/view/menu/m02;

    check-cast v0, Landroidx/appcompat/view/menu/ks1;

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/m02$b;->j()Landroidx/appcompat/view/menu/s32;

    move-result-object p1

    check-cast p1, Landroidx/appcompat/view/menu/m02;

    check-cast p1, Landroidx/appcompat/view/menu/ls1;

    invoke-static {v0, p1}, Landroidx/appcompat/view/menu/ks1;->H(Landroidx/appcompat/view/menu/ks1;Landroidx/appcompat/view/menu/ls1;)V

    return-object p0
.end method

.method public final t(I)Landroidx/appcompat/view/menu/ls1;
    .locals 1

    iget-object p1, p0, Landroidx/appcompat/view/menu/m02$b;->n:Landroidx/appcompat/view/menu/m02;

    check-cast p1, Landroidx/appcompat/view/menu/ks1;

    const/4 v0, 0x0

    invoke-virtual {p1, v0}, Landroidx/appcompat/view/menu/ks1;->G(I)Landroidx/appcompat/view/menu/ls1;

    move-result-object p1

    return-object p1
.end method
