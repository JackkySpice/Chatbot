.class public final Landroidx/appcompat/view/menu/bo;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/e81;


# static fields
.field public static final a:Landroidx/appcompat/view/menu/bo;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Landroidx/appcompat/view/menu/bo;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/bo;-><init>()V

    sput-object v0, Landroidx/appcompat/view/menu/bo;->a:Landroidx/appcompat/view/menu/bo;

    return-void
.end method

.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public a(Landroidx/appcompat/view/menu/c81;)Landroidx/appcompat/view/menu/c81;
    .locals 1

    const-string v0, "tracker"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p1
.end method
