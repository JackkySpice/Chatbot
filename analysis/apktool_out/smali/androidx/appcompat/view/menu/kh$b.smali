.class public final Landroidx/appcompat/view/menu/kh$b;
.super Landroidx/appcompat/view/menu/d80;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/xw;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Landroidx/appcompat/view/menu/kh;->a(Landroidx/appcompat/view/menu/jh;Landroidx/appcompat/view/menu/jh;Z)Landroidx/appcompat/view/menu/jh;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation


# instance fields
.field public final synthetic n:Landroidx/appcompat/view/menu/xn0;

.field public final synthetic o:Z


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/xn0;Z)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/kh$b;->n:Landroidx/appcompat/view/menu/xn0;

    iput-boolean p2, p0, Landroidx/appcompat/view/menu/kh$b;->o:Z

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Landroidx/appcompat/view/menu/d80;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final a(Landroidx/appcompat/view/menu/jh;Landroidx/appcompat/view/menu/jh$b;)Landroidx/appcompat/view/menu/jh;
    .locals 0

    invoke-interface {p1, p2}, Landroidx/appcompat/view/menu/jh;->o(Landroidx/appcompat/view/menu/jh;)Landroidx/appcompat/view/menu/jh;

    move-result-object p1

    return-object p1
.end method

.method public bridge synthetic h(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Landroidx/appcompat/view/menu/jh;

    check-cast p2, Landroidx/appcompat/view/menu/jh$b;

    invoke-virtual {p0, p1, p2}, Landroidx/appcompat/view/menu/kh$b;->a(Landroidx/appcompat/view/menu/jh;Landroidx/appcompat/view/menu/jh$b;)Landroidx/appcompat/view/menu/jh;

    move-result-object p1

    return-object p1
.end method
