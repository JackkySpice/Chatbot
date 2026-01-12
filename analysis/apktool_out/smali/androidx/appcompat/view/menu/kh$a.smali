.class public final Landroidx/appcompat/view/menu/kh$a;
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


# static fields
.field public static final n:Landroidx/appcompat/view/menu/kh$a;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Landroidx/appcompat/view/menu/kh$a;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/kh$a;-><init>()V

    sput-object v0, Landroidx/appcompat/view/menu/kh$a;->n:Landroidx/appcompat/view/menu/kh$a;

    return-void
.end method

.method public constructor <init>()V
    .locals 1

    const/4 v0, 0x2

    invoke-direct {p0, v0}, Landroidx/appcompat/view/menu/d80;-><init>(I)V

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

    invoke-virtual {p0, p1, p2}, Landroidx/appcompat/view/menu/kh$a;->a(Landroidx/appcompat/view/menu/jh;Landroidx/appcompat/view/menu/jh$b;)Landroidx/appcompat/view/menu/jh;

    move-result-object p1

    return-object p1
.end method
