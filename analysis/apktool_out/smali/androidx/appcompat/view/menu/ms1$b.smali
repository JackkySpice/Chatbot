.class public final Landroidx/appcompat/view/menu/ms1$b;
.super Landroidx/appcompat/view/menu/m02$b;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/w32;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/view/menu/ms1;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "b"
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-static {}, Landroidx/appcompat/view/menu/ms1;->J()Landroidx/appcompat/view/menu/ms1;

    move-result-object v0

    invoke-direct {p0, v0}, Landroidx/appcompat/view/menu/m02$b;-><init>(Landroidx/appcompat/view/menu/m02;)V

    return-void
.end method

.method public synthetic constructor <init>(Landroidx/appcompat/view/menu/bs1;)V
    .locals 0

    .line 2
    invoke-direct {p0}, Landroidx/appcompat/view/menu/ms1$b;-><init>()V

    return-void
.end method


# virtual methods
.method public final r(Landroidx/appcompat/view/menu/hs1$a;)Landroidx/appcompat/view/menu/ms1$b;
    .locals 1

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/m02$b;->n()V

    iget-object v0, p0, Landroidx/appcompat/view/menu/m02$b;->n:Landroidx/appcompat/view/menu/m02;

    check-cast v0, Landroidx/appcompat/view/menu/ms1;

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/m02$b;->j()Landroidx/appcompat/view/menu/s32;

    move-result-object p1

    check-cast p1, Landroidx/appcompat/view/menu/m02;

    check-cast p1, Landroidx/appcompat/view/menu/hs1;

    invoke-static {v0, p1}, Landroidx/appcompat/view/menu/ms1;->I(Landroidx/appcompat/view/menu/ms1;Landroidx/appcompat/view/menu/hs1;)V

    return-object p0
.end method
